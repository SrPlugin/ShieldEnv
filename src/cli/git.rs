use std::path::{Path, PathBuf};
use std::process::{self, ExitCode};

use shieldenv::app::merge_vaults;
use shieldenv::crypto::{Envelope, MAX_VAULT_LEN, inspect};
use shieldenv::storage::file::{WriteMode, read_bounded, write_atomic};
use shieldenv::{Error, Result};
use zeroize::Zeroizing;

use super::auth::Authenticator;
use super::output::notice;

const ATTRIBUTES_LINE: &str = "**/.shieldenv/*.vault merge=shieldenv";
const ATTRIBUTES_LIMIT: usize = 1 << 20;

pub(super) fn merge(base: &Path, ours: &Path, theirs: &Path) -> Result<ExitCode> {
    let base_bytes = read_vault(base)?;
    let our_bytes = read_vault(ours)?;
    let their_bytes = read_vault(theirs)?;
    if base_bytes.is_empty() {
        return Err(Error::MergeConflict(
            "the vault was created independently on both sides".to_owned(),
        ));
    }
    let authenticator = Authenticator::new();
    let inspection = inspect(&our_bytes)?;
    let ((), credentials) = authenticator.authenticate("merge", &inspection, |unlock| {
        Envelope::open(&our_bytes, unlock).map(drop)
    })?;
    let unlock = credentials.as_unlock().ok_or(Error::NoAccess)?;
    let merged = merge_vaults(&base_bytes, &our_bytes, &their_bytes, unlock)?;
    authenticator.check_trust(&inspect(&merged)?)?;
    write_atomic(ours, &merged, WriteMode::Replace)?;
    notice("merged vault");
    Ok(ExitCode::SUCCESS)
}

pub(super) fn setup(working_directory: &Path) -> Result<ExitCode> {
    let root = PathBuf::from(git(working_directory, &["rev-parse", "--show-toplevel"])?.trim());
    let attributes = root.join(".gitattributes");
    let existing = read_bounded(&attributes, ATTRIBUTES_LIMIT)?
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default();
    if !existing.lines().any(|line| line.trim() == ATTRIBUTES_LINE) {
        let mut updated = existing;
        if !updated.is_empty() && !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated.push_str(ATTRIBUTES_LINE);
        updated.push('\n');
        write_atomic(&attributes, updated.as_bytes(), WriteMode::Replace)?;
        notice(format!(
            "added the vault merge rule to {}",
            attributes.display()
        ));
    }
    let executable = std::env::current_exe().map_err(Error::Terminal)?;
    let driver = format!("{} merge %O %A %B", shell_quote(&executable));
    git(
        working_directory,
        &[
            "config",
            "--local",
            "merge.shieldenv.name",
            "ShieldEnv vault merge",
        ],
    )?;
    git(
        working_directory,
        &["config", "--local", "merge.shieldenv.driver", &driver],
    )?;
    notice(
        "git will now merge vault files key by key; commit .gitattributes and run \
         'shieldenv git-setup' once in every clone",
    );
    Ok(ExitCode::SUCCESS)
}

fn read_vault(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    read_bounded(path, MAX_VAULT_LEN)?.ok_or_else(|| Error::Io {
        path: path.to_path_buf(),
        source: std::io::ErrorKind::NotFound.into(),
    })
}

fn git(directory: &Path, arguments: &[&str]) -> Result<String> {
    let output = process::Command::new("git")
        .current_dir(directory)
        .args(arguments)
        .output()
        .map_err(|source| Error::Spawn {
            program: "git".to_owned(),
            source,
        })?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(Error::InvalidValue("this is not a git repository"))
    }
}

fn shell_quote(path: &Path) -> String {
    let text = path.to_string_lossy();
    let text = if cfg!(windows) {
        text.replace('\\', "/")
    } else {
        text.into_owned()
    };
    format!("'{}'", text.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_quoted_for_the_shell() {
        assert_eq!(
            shell_quote(Path::new("/usr/bin/shieldenv")),
            "'/usr/bin/shieldenv'"
        );
        if !cfg!(windows) {
            assert_eq!(shell_quote(Path::new("/a b/it's")), "'/a b/it'\\''s'");
        }
    }
}
