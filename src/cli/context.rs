use std::cell::RefCell;

use secrecy::SecretString;
use shieldenv::app::{Access, Vault};
use shieldenv::crypto::{Identity, Inspection};
use shieldenv::domain::Environment;
use shieldenv::storage::keystore::{self, Located, Sources};
use shieldenv::storage::{AuditLog, Workspace};
use shieldenv::{Error, Result};

use super::output::notice;
use super::prompt::Prompter;

const PASSWORD_ACTOR: &str = "password";

#[derive(Debug, Default)]
pub(super) struct Credentials {
    pub(super) password: Option<SecretString>,
    pub(super) identity: Option<Identity>,
}

pub(super) struct Context {
    pub(super) workspace: Workspace,
    pub(super) environment: Environment,
    pub(super) prompter: Prompter,
    identities: Sources,
    actor: RefCell<Option<String>>,
}

impl Context {
    pub(super) fn new(workspace: Workspace, environment: Environment) -> Self {
        Self {
            workspace,
            environment,
            prompter: Prompter::from_environment(),
            identities: Sources::from_environment(),
            actor: RefCell::new(None),
        }
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
        if let Some(identity) = self.member_identity(&inspection)? {
            let vault = Vault::open(&self.workspace, environment, &identity, access)?;
            self.set_actor(actor_name(&inspection, &identity));
            return Ok((
                vault,
                Credentials {
                    password: None,
                    identity: Some(identity),
                },
            ));
        }
        if !inspection.has_password {
            return Err(if keystore::locate(&self.identities)?.is_some() {
                Error::NotAMember
            } else {
                Error::NoPasswordAccess
            });
        }
        let (vault, password) = self.prompter.unlock(environment, |password| {
            Vault::open(&self.workspace, environment, password, access)
        })?;
        self.set_actor(PASSWORD_ACTOR.to_owned());
        Ok((
            vault,
            Credentials {
                password: Some(password),
                identity: None,
            },
        ))
    }

    pub(super) fn open_reusing(
        &self,
        environment: &Environment,
        access: Access,
        credentials: &Credentials,
    ) -> Result<Vault> {
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
        let password = self.prompter.initial_password(environment)?;
        Vault::create(&self.workspace, environment, &password)
    }

    pub(super) fn active_identity(&self) -> Result<Identity> {
        let located = keystore::locate(&self.identities)?.ok_or(Error::NoIdentity)?;
        self.unlock_identity(located)
    }

    pub(super) fn identity_for(&self, credentials: Credentials) -> Result<Identity> {
        match credentials.identity {
            Some(identity) => Ok(identity),
            None => self.active_identity(),
        }
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
        let actor = self.actor.borrow();
        let log = AuditLog::new(self.workspace.audit_path());
        if let Err(error) = log.record(action, environment, keys, ok, actor.as_deref()) {
            notice(format!("warning: audit log not written: {error}"));
        }
    }

    fn member_identity(&self, inspection: &Inspection) -> Result<Option<Identity>> {
        if inspection.members.is_empty() {
            return Ok(None);
        }
        let Some(located) = keystore::locate(&self.identities)? else {
            return Ok(None);
        };
        let is_member = inspection
            .members
            .iter()
            .any(|member| member.public == *located.public());
        if is_member {
            self.unlock_identity(located).map(Some)
        } else {
            Ok(None)
        }
    }

    fn unlock_identity(&self, located: Located) -> Result<Identity> {
        let mut remaining = self.prompter.identity_attempts();
        let mut candidate = Some(located);
        loop {
            let current = match candidate.take() {
                Some(located) => located,
                None => keystore::locate(&self.identities)?.ok_or(Error::NoIdentity)?,
            };
            match current.unlock(|| self.prompter.identity_passphrase()) {
                Err(Error::Authentication) if remaining > 1 => {
                    remaining -= 1;
                    notice("wrong passphrase, try again");
                }
                result => return result,
            }
        }
    }

    fn set_actor(&self, actor: String) {
        *self.actor.borrow_mut() = Some(actor);
    }
}

fn actor_name(inspection: &Inspection, identity: &Identity) -> String {
    let public = identity.public();
    inspection
        .members
        .iter()
        .find(|member| member.public == public)
        .map_or_else(|| public.fingerprint(), |member| member.name.to_string())
}
