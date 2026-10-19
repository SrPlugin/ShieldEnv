use std::io;
use std::path::{Path, PathBuf};

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "not a shieldenv project (or any parent directory); run 'shieldenv init' or use --global"
    )]
    NotAProject,
    #[error("refusing to use {}: it is not owned by the current user", .0.display())]
    UnsafeDirectory(PathBuf),
    #[error("no user data directory available on this platform")]
    NoDataDirectory,
    #[error("no vault for environment '{0}'")]
    VaultNotFound(String),
    #[error("vault was opened read-only")]
    ReadOnly,
    #[error("invalid identity: {0}")]
    InvalidIdentity(&'static str),
    #[error("wrong password or tampered vault")]
    Authentication,
    #[error("malformed vault: {0}")]
    Malformed(&'static str),
    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u8),
    #[error("invalid key {0:?}: use letters, digits and '_', not starting with a digit")]
    InvalidKey(String),
    #[error("invalid value: {0}")]
    InvalidValue(&'static str),
    #[error("invalid environment {0:?}: use lowercase letters, digits, '-' and '_'")]
    InvalidEnvironment(String),
    #[error("invalid pattern {0:?}: use key characters, '*' and '?'")]
    InvalidPattern(String),
    #[error("source and target environments must differ")]
    SameEnvironment,
    #[error("key '{0}' already exists; use --force to replace it")]
    KeyExists(String),
    #[error("key '{0}' not found")]
    KeyNotFound(String),
    #[error("password must be at least {0} characters")]
    WeakPassword(usize),
    #[error("passwords do not match")]
    PasswordMismatch,
    #[error("invalid shares: {0}")]
    Shares(&'static str),
    #[error("limit exceeded: {0}")]
    LimitExceeded(&'static str),
    #[error("{} already exists", .0.display())]
    AlreadyExists(PathBuf),
    #[error("{}: {source}", path.display())]
    Io { path: PathBuf, source: io::Error },
    #[error("cannot run '{program}': {source}")]
    Spawn { program: String, source: io::Error },
    #[error(transparent)]
    Terminal(io::Error),
    #[error("operating system random number generator failed")]
    Random,
}

impl Error {
    #[must_use]
    pub fn is_broken_pipe(&self) -> bool {
        matches!(self, Self::Terminal(source) if source.kind() == io::ErrorKind::BrokenPipe)
    }
}

pub trait IoContext<T> {
    fn at(self, path: &Path) -> Result<T>;
}

impl<T> IoContext<T> for io::Result<T> {
    fn at(self, path: &Path) -> Result<T> {
        self.map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })
    }
}
