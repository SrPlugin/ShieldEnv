use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use super::file::{WriteMode, create_private_dir, is_real_directory, write_atomic};
use crate::domain::Environment;
use crate::{Error, IoContext, Result};

pub const DIR_NAME: &str = ".shieldenv";
const GLOBAL_DIR_NAME: &str = "shieldenv";
const VAULT_EXTENSION: &str = "vault";
const LOCK_EXTENSION: &str = "lock";
const AUDIT_FILE: &str = "audit.log";
const HISTORY_DIR: &str = "history";
const GITIGNORE: &[u8] = b"*.lock\naudit.log\nhistory/\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Project,
    Global,
}

impl fmt::Display for Scope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Project => "project",
            Self::Global => "global",
        })
    }
}

#[derive(Debug, Clone)]
pub struct Workspace {
    directory: PathBuf,
    scope: Scope,
}

impl Workspace {
    pub fn locate(scope: Scope, working_directory: &Path) -> Result<Self> {
        match scope {
            Scope::Project => Self::find_project(working_directory)?.ok_or(Error::NotAProject),
            Scope::Global => {
                let directory = global_directory()?;
                create_private_dir(&directory)?;
                Self::verified(directory, Scope::Global)
            }
        }
    }

    pub fn find_project(start: &Path) -> Result<Option<Self>> {
        start
            .ancestors()
            .map(|ancestor| ancestor.join(DIR_NAME))
            .find(|candidate| is_real_directory(candidate))
            .map(|directory| Self::verified(directory, Scope::Project))
            .transpose()
    }

    pub fn init(scope: Scope, working_directory: &Path) -> Result<(Self, bool)> {
        let directory = match scope {
            Scope::Project => working_directory.join(DIR_NAME),
            Scope::Global => global_directory()?,
        };
        let created = create_private_dir(&directory)?;
        let workspace = Self::verified(directory, scope)?;
        if scope == Scope::Project {
            match write_atomic(
                &workspace.directory.join(".gitignore"),
                GITIGNORE,
                WriteMode::CreateNew,
            ) {
                Ok(()) | Err(Error::AlreadyExists(_)) => {}
                Err(error) => return Err(error),
            }
        }
        Ok((workspace, created))
    }

    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    #[must_use]
    pub fn scope(&self) -> Scope {
        self.scope
    }

    #[must_use]
    pub fn vault_path(&self, environment: &Environment) -> PathBuf {
        self.directory
            .join(format!("{environment}.{VAULT_EXTENSION}"))
    }

    #[must_use]
    pub fn lock_path(&self, environment: &Environment) -> PathBuf {
        self.directory
            .join(format!("{environment}.{LOCK_EXTENSION}"))
    }

    #[must_use]
    pub fn history_path(&self, environment: &Environment) -> PathBuf {
        self.directory.join(HISTORY_DIR).join(environment.as_str())
    }

    #[must_use]
    pub fn audit_path(&self) -> PathBuf {
        self.directory.join(AUDIT_FILE)
    }

    pub fn environments(&self) -> Result<Vec<Environment>> {
        let mut environments: Vec<Environment> = fs::read_dir(&self.directory)
            .at(&self.directory)?
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
            .filter_map(|entry| {
                entry
                    .file_name()
                    .to_str()?
                    .strip_suffix(&format!(".{VAULT_EXTENSION}"))?
                    .parse()
                    .ok()
            })
            .collect();
        environments.sort();
        Ok(environments)
    }

    fn verified(directory: PathBuf, scope: Scope) -> Result<Self> {
        if is_owned_by_current_user(&directory)? {
            Ok(Self { directory, scope })
        } else {
            Err(Error::UnsafeDirectory(directory))
        }
    }
}

fn global_directory() -> Result<PathBuf> {
    dirs::data_dir()
        .map(|directory| directory.join(GLOBAL_DIR_NAME))
        .ok_or(Error::NoDataDirectory)
}

#[cfg(unix)]
fn is_owned_by_current_user(path: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let metadata = path.symlink_metadata().at(path)?;
    Ok(metadata.uid() == rustix::process::geteuid().as_raw())
}

#[cfg(not(unix))]
fn is_owned_by_current_user(path: &Path) -> Result<bool> {
    path.symlink_metadata().at(path).map(|_| true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment(name: &str) -> Environment {
        name.parse().unwrap()
    }

    #[test]
    fn init_creates_private_directory_and_gitignore() {
        let root = tempfile::tempdir().unwrap();
        let (workspace, created) = Workspace::init(Scope::Project, root.path()).unwrap();
        assert!(created);
        assert_eq!(workspace.directory(), root.path().join(DIR_NAME));
        assert_eq!(
            fs::read(workspace.directory().join(".gitignore")).unwrap(),
            GITIGNORE
        );
        let (_, created_again) = Workspace::init(Scope::Project, root.path()).unwrap();
        assert!(!created_again);
    }

    #[test]
    fn discovery_walks_up_to_the_nearest_project() {
        let root = tempfile::tempdir().unwrap();
        Workspace::init(Scope::Project, root.path()).unwrap();
        let nested = root.path().join("a").join("b");
        fs::create_dir_all(&nested).unwrap();
        let found = Workspace::find_project(&nested).unwrap().unwrap();
        assert_eq!(found.directory(), root.path().join(DIR_NAME));
        assert_eq!(found.scope(), Scope::Project);
        Workspace::init(Scope::Project, &nested).unwrap();
        let closest = Workspace::find_project(&nested).unwrap().unwrap();
        assert_eq!(closest.directory(), nested.join(DIR_NAME));
    }

    #[test]
    fn regular_files_named_like_the_directory_are_ignored() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("project");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join(DIR_NAME), b"").unwrap();
        let found = Workspace::find_project(&nested).unwrap();
        assert!(found.is_none_or(|workspace| workspace.directory() != nested.join(DIR_NAME)));
    }

    #[test]
    fn paths_are_derived_from_environment_names() {
        let root = tempfile::tempdir().unwrap();
        let (workspace, _) = Workspace::init(Scope::Project, root.path()).unwrap();
        let production = environment("production");
        assert_eq!(
            workspace.vault_path(&production),
            workspace.directory().join("production.vault")
        );
        assert_eq!(
            workspace.lock_path(&production),
            workspace.directory().join("production.lock")
        );
        assert_eq!(
            workspace.audit_path(),
            workspace.directory().join("audit.log")
        );
        assert_eq!(
            workspace.history_path(&production),
            workspace.directory().join("history").join("production")
        );
    }

    #[test]
    fn environments_lists_valid_vaults_sorted() {
        let root = tempfile::tempdir().unwrap();
        let (workspace, _) = Workspace::init(Scope::Project, root.path()).unwrap();
        for name in [
            "staging.vault",
            "dev.vault",
            "Bad.vault",
            "notes.txt",
            "dev.lock",
        ] {
            fs::write(workspace.directory().join(name), b"").unwrap();
        }
        fs::create_dir(workspace.directory().join("dir.vault")).unwrap();
        assert_eq!(
            workspace.environments().unwrap(),
            [environment("dev"), environment("staging")]
        );
    }
}
