use secrecy::SecretString;
use shieldenv::app::{Access, Vault};
use shieldenv::domain::Environment;
use shieldenv::storage::{AuditLog, Workspace};
use shieldenv::{Error, Result};

use super::output::notice;
use super::prompt::Prompter;

pub(super) struct Context {
    pub(super) workspace: Workspace,
    pub(super) environment: Environment,
    pub(super) prompter: Prompter,
}

impl Context {
    pub(super) fn open(&self, environment: &Environment, access: Access) -> Result<Vault> {
        self.unlock(environment, access).map(|(vault, _)| vault)
    }

    pub(super) fn unlock(
        &self,
        environment: &Environment,
        access: Access,
    ) -> Result<(Vault, SecretString)> {
        if !Vault::exists(&self.workspace, environment) {
            return Err(Error::VaultNotFound(environment.to_string()));
        }
        self.prompter.unlock(environment, |password| {
            Vault::open(&self.workspace, environment, password, access)
        })
    }

    pub(super) fn open_reusing(
        &self,
        environment: &Environment,
        access: Access,
        password: &SecretString,
    ) -> Result<Vault> {
        match Vault::open(&self.workspace, environment, password, access) {
            Err(Error::Authentication) => self.open(environment, access),
            result => result,
        }
    }

    pub(super) fn open_or_create(&self, environment: &Environment) -> Result<Vault> {
        if Vault::exists(&self.workspace, environment) {
            return self.open(environment, Access::Write);
        }
        notice(format!("creating vault for '{environment}'"));
        let password = self.prompter.initial_password(environment)?;
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
        if let Err(error) =
            AuditLog::new(self.workspace.audit_path()).record(action, environment, keys, ok)
        {
            notice(format!("warning: audit log not written: {error}"));
        }
    }
}
