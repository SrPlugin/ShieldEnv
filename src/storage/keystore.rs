use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use super::file::{WriteMode, create_private_dir, read_bounded, write_atomic};
use crate::crypto::identity_file::{self, MAX_FILE_LEN};
use crate::crypto::{Identity, PublicIdentity};
use crate::{Error, Result};

pub const IDENTITY_VARIABLE: &str = "SHIELDENV_IDENTITY";
pub const IDENTITY_FILE_VARIABLE: &str = "SHIELDENV_IDENTITY_FILE";
pub const NO_KEYRING_VARIABLE: &str = "SHIELDENV_NO_KEYRING";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    Environment,
    File(PathBuf),
    Keyring,
}

#[derive(Debug, Default)]
pub struct Sources {
    pub inline: Option<SecretString>,
    pub file: Option<PathBuf>,
    pub default_file: Option<PathBuf>,
    pub keyring: bool,
}

impl Sources {
    #[must_use]
    pub fn from_environment() -> Self {
        let variable = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
        Self {
            inline: variable(IDENTITY_VARIABLE).map(SecretString::from),
            file: variable(IDENTITY_FILE_VARIABLE).map(PathBuf::from),
            default_file: default_path(),
            keyring: cfg!(feature = "keyring") && variable(NO_KEYRING_VARIABLE).is_none(),
        }
    }
}

enum Material {
    Ready(Box<Identity>),
    Stored(Zeroizing<Vec<u8>>),
}

pub struct Located {
    origin: Origin,
    public: PublicIdentity,
    material: Material,
}

impl Located {
    #[must_use]
    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    #[must_use]
    pub fn public(&self) -> &PublicIdentity {
        &self.public
    }

    pub fn unlock(self, passphrase: impl FnOnce() -> Result<SecretString>) -> Result<Identity> {
        match self.material {
            Material::Ready(identity) => Ok(*identity),
            Material::Stored(bytes) if identity_file::is_encrypted(&bytes) => {
                identity_file::open(&bytes, Some(&passphrase()?))
            }
            Material::Stored(bytes) => identity_file::open(&bytes, None),
        }
    }
}

impl std::fmt::Debug for Located {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Located")
            .field("origin", &self.origin)
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

#[must_use]
pub fn default_path() -> Option<PathBuf> {
    dirs::config_dir().map(|directory| directory.join("shieldenv").join("identity"))
}

pub fn locate(sources: &Sources) -> Result<Option<Located>> {
    if let Some(text) = &sources.inline {
        let identity = Identity::from_secret_text(text.expose_secret())?;
        return Ok(Some(Located {
            origin: Origin::Environment,
            public: identity.public(),
            material: Material::Ready(Box::new(identity)),
        }));
    }
    if let Some(path) = &sources.file {
        return load(path, true);
    }
    let stored = match &sources.default_file {
        Some(path) => load(path, false)?,
        None => None,
    };
    if stored.is_some() || !sources.keyring {
        return Ok(stored);
    }
    from_keyring()
}

#[cfg(feature = "keyring")]
fn from_keyring() -> Result<Option<Located>> {
    let Ok(Some(text)) = super::keyring::load() else {
        return Ok(None);
    };
    let identity = Identity::from_secret_text(&text)?;
    Ok(Some(Located {
        origin: Origin::Keyring,
        public: identity.public(),
        material: Material::Ready(Box::new(identity)),
    }))
}

#[cfg(not(feature = "keyring"))]
#[allow(clippy::unnecessary_wraps)]
fn from_keyring() -> Result<Option<Located>> {
    Ok(None)
}

pub fn create(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        create_private_dir(parent)?;
    }
    write_atomic(path, contents, WriteMode::CreateNew)
}

fn load(path: &Path, required: bool) -> Result<Option<Located>> {
    let Some(bytes) = read_bounded(path, MAX_FILE_LEN)? else {
        return if required {
            Err(Error::Io {
                path: path.to_path_buf(),
                source: std::io::ErrorKind::NotFound.into(),
            })
        } else {
            Ok(None)
        };
    };
    if !identity_file::is_encrypted(&bytes) && !is_private(path) {
        return Err(Error::InsecurePermissions(path.to_path_buf()));
    }
    Ok(Some(Located {
        origin: Origin::File(path.to_path_buf()),
        public: identity_file::public_of(&bytes)?,
        material: Material::Stored(bytes),
    }))
}

#[cfg(unix)]
fn is_private(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .is_ok_and(|metadata| metadata.permissions().mode().trailing_zeros() >= 6)
}

#[cfg(not(unix))]
fn is_private(_path: &Path) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn passphrase(text: &str) -> SecretString {
        SecretString::from(text.to_owned())
    }

    fn plain_file(directory: &Path, name: &str, identity: &Identity) -> PathBuf {
        let path = directory.join(name);
        create(&path, identity.secret_text().as_bytes()).unwrap();
        path
    }

    #[cfg(feature = "keyring")]
    #[test]
    fn the_keyring_is_the_last_resort() {
        crate::storage::keyring::use_mock_store();
        let stored = Identity::generate().unwrap();
        crate::storage::keyring::save(&stored.secret_text()).unwrap();
        let only_keyring = Sources {
            keyring: true,
            ..Sources::default()
        };
        let located = locate(&only_keyring).unwrap().unwrap();
        assert_eq!(located.origin(), &Origin::Keyring);
        assert_eq!(located.public(), &stored.public());
        let directory = tempfile::tempdir().unwrap();
        let on_disk = Identity::generate().unwrap();
        let both = Sources {
            default_file: Some(plain_file(directory.path(), "identity", &on_disk)),
            keyring: true,
            ..Sources::default()
        };
        let located = locate(&both).unwrap().unwrap();
        assert!(matches!(located.origin(), Origin::File(_)));
        assert_eq!(located.public(), &on_disk.public());
        assert!(locate(&Sources::default()).unwrap().is_none());
    }

    #[test]
    fn nothing_found_when_no_source_exists() {
        let directory = tempfile::tempdir().unwrap();
        let sources = Sources {
            default_file: Some(directory.path().join("missing")),
            ..Sources::default()
        };
        assert!(locate(&sources).unwrap().is_none());
        assert!(locate(&Sources::default()).unwrap().is_none());
    }

    #[test]
    fn inline_identity_has_priority_and_needs_no_passphrase() {
        let directory = tempfile::tempdir().unwrap();
        let inline = Identity::generate().unwrap();
        let on_disk = Identity::generate().unwrap();
        let sources = Sources {
            inline: Some(SecretString::from(inline.secret_text().to_string())),
            file: Some(plain_file(directory.path(), "other", &on_disk)),
            ..Sources::default()
        };
        let located = locate(&sources).unwrap().unwrap();
        assert_eq!(located.origin(), &Origin::Environment);
        assert_eq!(located.public(), &inline.public());
        let identity = located.unlock(|| panic!("no passphrase expected")).unwrap();
        assert_eq!(identity.public(), inline.public());
    }

    #[test]
    fn explicit_file_beats_default_and_must_exist() {
        let directory = tempfile::tempdir().unwrap();
        let explicit = Identity::generate().unwrap();
        let default = Identity::generate().unwrap();
        let explicit_path = plain_file(directory.path(), "explicit", &explicit);
        let default_path = plain_file(directory.path(), "default", &default);
        let sources = Sources {
            file: Some(explicit_path.clone()),
            default_file: Some(default_path),
            ..Sources::default()
        };
        let located = locate(&sources).unwrap().unwrap();
        assert_eq!(located.origin(), &Origin::File(explicit_path));
        assert_eq!(located.public(), &explicit.public());
        let missing = Sources {
            file: Some(directory.path().join("nope")),
            ..Sources::default()
        };
        assert!(matches!(locate(&missing), Err(Error::Io { .. })));
    }

    #[test]
    fn encrypted_files_reveal_the_public_part_without_a_passphrase() {
        let directory = tempfile::tempdir().unwrap();
        let identity = Identity::generate().unwrap();
        let sealed = identity_file::seal(&identity, &passphrase("long enough passphrase")).unwrap();
        let path = directory.path().join("identity");
        create(&path, &sealed).unwrap();
        let sources = Sources {
            default_file: Some(path),
            ..Sources::default()
        };
        let located = locate(&sources).unwrap().unwrap();
        assert_eq!(located.public(), &identity.public());
        let opened = located
            .unlock(|| Ok(passphrase("long enough passphrase")))
            .unwrap();
        assert_eq!(opened.public(), identity.public());
        let wrong = locate(&sources).unwrap().unwrap();
        assert!(matches!(
            wrong.unlock(|| Ok(passphrase("not the passphrase!"))),
            Err(Error::Authentication)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn plain_identity_files_must_be_private() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = plain_file(directory.path(), "identity", &Identity::generate().unwrap());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let sources = Sources {
            file: Some(path),
            ..Sources::default()
        };
        assert!(matches!(
            locate(&sources),
            Err(Error::InsecurePermissions(_))
        ));
    }

    #[test]
    fn create_never_overwrites_and_protects_the_directory() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join("config")
            .join("shieldenv")
            .join("identity");
        create(&path, b"first").unwrap();
        assert!(matches!(
            create(&path, b"second"),
            Err(Error::AlreadyExists(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), b"first");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(path.parent().unwrap()), 0o700);
        }
    }
}
