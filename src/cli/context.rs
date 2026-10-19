use shieldenv::app::{Access, Vault};
use shieldenv::crypto::{Identity, Inspection};
use shieldenv::domain::Environment;
use shieldenv::storage::{AuditLog, Workspace};
use shieldenv::{Error, Result};

use super::auth::{Authenticator, Credentials};
use super::output::notice;
use super::prompt::Prompter;

pub(super) struct Context {
    pub(super) workspace: Workspace,
    pub(super) environment: Environment,
    auth: Authenticator,
}

impl Context {
    pub(super) fn new(workspace: Workspace, environment: Environment) -> Self {
        Self {
            workspace,
            environment,
            auth: Authenticator::new(),
        }
    }

    pub(super) fn prompter(&self) -> &Prompter {
        &self.auth.prompter
    }

    pub(super) fn active_identity(&self) -> Result<Identity> {
        self.auth.active_identity()
    }

    pub(super) fn identity_for(&self, credentials: Credentials) -> Result<Identity> {
        self.auth.identity_for(credentials)
    }

    pub(super) fn open(&self, environment: &Environment, access: Access) -> Result<Vault> {
        self.unlock(environment, access).map(|(vault, _)| vault)
    }

    pub(super) fn unlock(
        &self,
        environment: &Environment,
        access: Access,
    ) -> Result<(Vault, Credentials)> {
        let inspection = Vault::inspect(&self.workspace, environment)?;
        self.auth
            .authenticate(environment.as_str(), &inspection, |unlock| {
                Vault::open(&self.workspace, environment, unlock, access)
            })
    }

    pub(super) fn trusted_inspection(&self, environment: &Environment) -> Result<Inspection> {
        let inspection = Vault::inspect(&self.workspace, environment)?;
        self.auth.check_trust(&inspection)?;
        Ok(inspection)
    }

    pub(super) fn accept_trust(&self) -> Result<bool> {
        let inspection = Vault::inspect(&self.workspace, &self.environment)?;
        self.auth.accept_trust(&inspection)
    }

    pub(super) fn open_reusing(
        &self,
        environment: &Environment,
        access: Access,
        credentials: &Credentials,
    ) -> Result<Vault> {
        self.trusted_inspection(environment)?;
        if let Some(identity) = &credentials.identity {
            match Vault::open(&self.workspace, environment, identity, access) {
                Err(Error::NotAMember) => {}
                result => return result,
            }
        }
        if let Some(password) = &credentials.password {
            match Vault::open(&self.workspace, environment, password, access) {
                Err(Error::Authentication | Error::NoPasswordAccess) => {}
                result => return result,
            }
        }
        self.open(environment, access)
    }

    pub(super) fn open_or_create(&self, environment: &Environment) -> Result<Vault> {
        if Vault::exists(&self.workspace, environment) {
            return self.open(environment, Access::Write);
        }
        notice(format!("creating vault for '{environment}'"));
        let password = self.prompter().initial_password(environment)?;
        Vault::create(&self.workspace, environment, &password)
    }

    pub(super) fn audited<T>(
        &self,
        action: &str,
        keys: &[&str],
        operation: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let result = operation();
        self.record(&self.environment, action, keys, result.is_ok());
        result
    }

    pub(super) fn record(&self, environment: &Environment, action: &str, keys: &[&str], ok: bool) {
        let actor = self.auth.actor();
        let log = AuditLog::new(self.workspace.audit_path());
        if let Err(error) = log.record(action, environment, keys, ok, actor.as_deref()) {
            notice(format!("warning: audit log not written: {error}"));
        }
    }
}
