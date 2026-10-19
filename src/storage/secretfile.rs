use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::{IoContext, Result};

#[derive(Debug)]
enum Backing {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Descriptor { _file: File },
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    Directory { _directory: tempfile::TempDir },
}

#[derive(Debug)]
pub struct DeliveredFile {
    path: PathBuf,
    backing: Backing,
}

impl DeliveredFile {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn survives_exec(&self) -> bool {
        matches!(self.backing, Backing::Descriptor { .. })
    }
}

#[cfg(target_os = "linux")]
pub fn deliver(_name: &str, contents: &str) -> Result<DeliveredFile> {
    use std::os::fd::AsRawFd;

    let memory = Path::new("memfd:shieldenv");
    let descriptor = rustix::fs::memfd_create("shieldenv", rustix::fs::MemfdFlags::empty())
        .map_err(std::io::Error::from)
        .at(memory)?;
    let mut file = File::from(descriptor);
    file.write_all(contents.as_bytes()).at(memory)?;
    Ok(DeliveredFile {
        path: PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())),
        backing: Backing::Descriptor { _file: file },
    })
}

#[cfg(not(target_os = "linux"))]
pub fn deliver(name: &str, contents: &str) -> Result<DeliveredFile> {
    use super::file::{WriteMode, write_atomic};

    let base = std::env::temp_dir();
    let directory = tempfile::Builder::new()
        .prefix("shieldenv-")
        .tempdir_in(&base)
        .at(&base)?;
    let path = directory.path().join(name);
    write_atomic(&path, contents.as_bytes(), WriteMode::CreateNew)?;
    Ok(DeliveredFile {
        path,
        backing: Backing::Directory {
            _directory: directory,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn delivered_files_hold_the_contents() {
        let first = deliver("FIRST", "-----BEGIN-----\nbody\n").unwrap();
        let second = deliver("SECOND", "other").unwrap();
        assert_ne!(first.path(), second.path());
        assert_eq!(
            fs::read_to_string(first.path()).unwrap(),
            "-----BEGIN-----\nbody\n"
        );
        assert_eq!(fs::read_to_string(second.path()).unwrap(), "other");
        assert_eq!(first.survives_exec(), cfg!(target_os = "linux"));
    }

    #[cfg(unix)]
    #[test]
    fn files_are_private_and_cleaned_up() {
        use std::os::unix::fs::PermissionsExt;
        let delivered = deliver("PRIVATE", "secret").unwrap();
        let path = delivered.path().to_path_buf();
        if delivered.survives_exec() {
            assert!(path.starts_with("/proc/self/fd"));
        } else {
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            drop(delivered);
            assert!(!path.exists());
        }
    }
}
