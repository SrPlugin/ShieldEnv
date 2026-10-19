use std::path::{Path, PathBuf};

use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::crypto::{Envelope, KdfParams, Key, MAX_VAULT_LEN};
use crate::domain::{Environment, Secrets};
use crate::storage::Workspace;
use crate::storage::codec;
use crate::storage::file::{FileLock, LockMode, WriteMode, read_bounded, write_atomic};
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

impl From<Access> for LockMode {
    fn from(access: Access) -> Self {
        match access {
            Access::Read => Self::Shared,
            Access::Write => Self::Exclusive,
        }
    }
}

#[derive(Debug)]
pub struct Vault {
    path: PathBuf,
    environment: Environment,
    access: Access,
    envelope: Envelope,
    secrets: Secrets,
    _lock: FileLock,
}

impl Vault {
    #[must_use]
    pub fn exists(workspace: &Workspace, environment: &Environment) -> bool {
        workspace.vault_path(environment).is_file()
    }

    pub fn open(
        workspace: &Workspace,
        environment: &Environment,
        password: &SecretString,
        access: Access,
    ) -> Result<Self> {
        Self::load(workspace, environment, access, |blob| {
            Envelope::open(blob, password)
        })
    }

    pub fn open_with_key(
        workspace: &Workspace,
        environment: &Environment,
        data_key: Key,
        access: Access,
    ) -> Result<Self> {
        Self::load(workspace, environment, access, |blob| {
            Envelope::open_with_key(blob, data_key)
        })
    }

    pub fn create(
        workspace: &Workspace,
        environment: &Environment,
        password: &SecretString,
    ) -> Result<Self> {
        Self::initialize(workspace, environment, Envelope::create(password)?)
    }

    pub fn create_sibling(
        &self,
        workspace: &Workspace,
        environment: &Environment,
        password: &SecretString,
    ) -> Result<Self> {
        Self::initialize(workspace, environment, self.envelope.reseal_for(password)?)
    }

    pub fn save(&self) -> Result<()> {
        if self.access != Access::Write {
            return Err(Error::ReadOnly);
        }
        write_atomic(&self.path, &self.encrypt()?, WriteMode::Replace)
    }

    pub fn change_password(&mut self, password: &SecretString) -> Result<()> {
        if self.access != Access::Write {
            return Err(Error::ReadOnly);
        }
        self.envelope.rewrap(password)?;
        self.save()
    }

    #[must_use]
    pub fn secrets(&self) -> &Secrets {
        &self.secrets
    }

    pub fn secrets_mut(&mut self) -> &mut Secrets {
        &mut self.secrets
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn environment(&self) -> &Environment {
        &self.environment
    }

    #[must_use]
    pub fn params(&self) -> KdfParams {
        self.envelope.params()
    }

    #[must_use]
    pub fn data_key(&self) -> &Key {
        self.envelope.data_key()
    }

    fn load(
        workspace: &Workspace,
        environment: &Environment,
        access: Access,
        unlock: impl FnOnce(&[u8]) -> Result<(Envelope, Zeroizing<Vec<u8>>)>,
    ) -> Result<Self> {
        let lock = FileLock::acquire(&workspace.lock_path(environment), access.into())?;
        let path = workspace.vault_path(environment);
        let blob = read_bounded(&path, MAX_VAULT_LEN)?
            .ok_or_else(|| Error::VaultNotFound(environment.to_string()))?;
        let (envelope, plaintext) = unlock(&blob)?;
        let secrets = codec::decode(&plaintext)?;
        Ok(Self {
            path,
            environment: environment.clone(),
            access,
            envelope,
            secrets,
            _lock: lock,
        })
    }

    fn initialize(
        workspace: &Workspace,
        environment: &Environment,
        envelope: Envelope,
    ) -> Result<Self> {
        let lock = FileLock::acquire(&workspace.lock_path(environment), LockMode::Exclusive)?;
        let vault = Self {
            path: workspace.vault_path(environment),
            environment: environment.clone(),
            access: Access::Write,
            envelope,
            secrets: Secrets::new(),
            _lock: lock,
        };
        write_atomic(&vault.path, &vault.encrypt()?, WriteMode::CreateNew)?;
        Ok(vault)
    }

    fn encrypt(&self) -> Result<Vec<u8>> {
        self.envelope.seal(&codec::encode(&self.secrets)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Scope;
    use std::fs;

    struct Fixture {
        _root: tempfile::TempDir,
        workspace: Workspace,
        environment: Environment,
    }

    fn fixture() -> Fixture {
        let root = tempfile::tempdir().unwrap();
        let (workspace, _) = Workspace::init(Scope::Project, root.path()).unwrap();
        Fixture {
            _root: root,
            workspace,
            environment: "dev".parse().unwrap(),
        }
    }

    fn password(text: &str) -> SecretString {
        SecretString::from(text.to_owned())
    }

    fn insert(vault: &mut Vault, key: &str, value: &str) {
        vault
            .secrets_mut()
            .insert(key.parse().unwrap(), Zeroizing::new(value.to_owned()))
            .unwrap();
    }

    #[test]
    fn create_save_and_reopen() {
        let fixture = fixture();
        let secret = password("correct horse battery");
        let mut vault = Vault::create(&fixture.workspace, &fixture.environment, &secret).unwrap();
        assert!(Vault::exists(&fixture.workspace, &fixture.environment));
        insert(&mut vault, "API_KEY", "value");
        vault.save().unwrap();
        drop(vault);
        let reopened = Vault::open(
            &fixture.workspace,
            &fixture.environment,
            &secret,
            Access::Read,
        )
        .unwrap();
        assert_eq!(reopened.secrets().get("API_KEY"), Some("value"));
        assert_eq!(reopened.params(), KdfParams::RECOMMENDED);
    }

    #[test]
    fn create_refuses_existing_vault() {
        let fixture = fixture();
        let secret = password("correct horse battery");
        drop(Vault::create(&fixture.workspace, &fixture.environment, &secret).unwrap());
        assert!(matches!(
            Vault::create(&fixture.workspace, &fixture.environment, &secret),
            Err(Error::AlreadyExists(_))
        ));
    }

    #[test]
    fn missing_vault_and_wrong_password_are_reported() {
        let fixture = fixture();
        assert!(matches!(
            Vault::open(
                &fixture.workspace,
                &fixture.environment,
                &password("x"),
                Access::Read
            ),
            Err(Error::VaultNotFound(_))
        ));
        drop(
            Vault::create(
                &fixture.workspace,
                &fixture.environment,
                &password("correct horse battery"),
            )
            .unwrap(),
        );
        assert!(matches!(
            Vault::open(
                &fixture.workspace,
                &fixture.environment,
                &password("wrong"),
                Access::Read
            ),
            Err(Error::Authentication)
        ));
    }

    #[test]
    fn read_access_cannot_write() {
        let fixture = fixture();
        let secret = password("correct horse battery");
        drop(Vault::create(&fixture.workspace, &fixture.environment, &secret).unwrap());
        let mut vault = Vault::open(
            &fixture.workspace,
            &fixture.environment,
            &secret,
            Access::Read,
        )
        .unwrap();
        assert!(matches!(vault.save(), Err(Error::ReadOnly)));
        assert!(matches!(
            vault.change_password(&password("another password")),
            Err(Error::ReadOnly)
        ));
    }

    #[test]
    fn password_change_keeps_secrets_and_data_key() {
        let fixture = fixture();
        let old = password("old password value");
        let new = password("new password value");
        let mut vault = Vault::create(&fixture.workspace, &fixture.environment, &old).unwrap();
        insert(&mut vault, "A", "1");
        vault.save().unwrap();
        let data_key = vault.data_key().clone();
        vault.change_password(&new).unwrap();
        drop(vault);
        assert!(Vault::open(&fixture.workspace, &fixture.environment, &old, Access::Read).is_err());
        let reopened = Vault::open_with_key(
            &fixture.workspace,
            &fixture.environment,
            data_key,
            Access::Read,
        )
        .unwrap();
        assert_eq!(reopened.secrets().get("A"), Some("1"));
        drop(reopened);
        assert!(Vault::open(&fixture.workspace, &fixture.environment, &new, Access::Read).is_ok());
    }

    #[test]
    fn sibling_vaults_share_password_but_not_keys() {
        let fixture = fixture();
        let secret = password("correct horse battery");
        let source = Vault::create(&fixture.workspace, &fixture.environment, &secret).unwrap();
        let staging: Environment = "staging".parse().unwrap();
        let sibling = source
            .create_sibling(&fixture.workspace, &staging, &secret)
            .unwrap();
        assert_ne!(**source.data_key(), **sibling.data_key());
        drop(sibling);
        assert!(Vault::open(&fixture.workspace, &staging, &secret, Access::Read).is_ok());
    }

    #[test]
    fn tampered_vault_is_rejected() {
        let fixture = fixture();
        let secret = password("correct horse battery");
        drop(Vault::create(&fixture.workspace, &fixture.environment, &secret).unwrap());
        let path = fixture.workspace.vault_path(&fixture.environment);
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x80;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            Vault::open(
                &fixture.workspace,
                &fixture.environment,
                &secret,
                Access::Read
            ),
            Err(Error::Authentication)
        ));
    }
}
