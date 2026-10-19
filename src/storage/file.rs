use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::path::Path;

use zeroize::Zeroizing;

use crate::{Error, IoContext, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    Replace,
    CreateNew,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    Shared,
    Exclusive,
}

#[derive(Debug)]
pub struct FileLock {
    _file: File,
}

impl FileLock {
    pub fn acquire(path: &Path, mode: LockMode) -> Result<Self> {
        let file = private_options()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .at(path)?;
        match mode {
            LockMode::Shared => file.lock_shared(),
            LockMode::Exclusive => file.lock(),
        }
        .at(path)?;
        Ok(Self { _file: file })
    }
}

pub fn read_bounded(path: &Path, limit: usize) -> Result<Option<Zeroizing<Vec<u8>>>> {
    read_with_metadata(path, limit).map(|found| found.map(|(bytes, _)| bytes))
}

pub fn read_with_metadata(
    path: &Path,
    limit: usize,
) -> Result<Option<(Zeroizing<Vec<u8>>, fs::Metadata)>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).at(path),
    };
    let metadata = file.metadata().at(path)?;
    if !metadata.is_file() {
        return Err(refuse_link(path));
    }
    let declared = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    if declared > limit {
        return Err(Error::LimitExceeded("file too large"));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(declared.saturating_add(1)));
    let ceiling = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    file.take(ceiling).read_to_end(&mut bytes).at(path)?;
    if bytes.len() > limit {
        return Err(Error::LimitExceeded("file too large"));
    }
    Ok(Some((bytes, metadata)))
}

pub fn write_atomic(path: &Path, contents: &[u8], mode: WriteMode) -> Result<()> {
    let directory = parent_directory(path);
    let mut temporary = tempfile::Builder::new()
        .prefix(".shieldenv-")
        .tempfile_in(directory)
        .at(directory)?;
    temporary.write_all(contents).at(path)?;
    temporary.as_file().sync_all().at(path)?;
    match mode {
        WriteMode::Replace => temporary
            .persist(path)
            .map(drop)
            .map_err(|error| error.error)
            .at(path)?,
        WriteMode::CreateNew => {
            temporary
                .persist_noclobber(path)
                .map(drop)
                .map_err(|error| match error.error.kind() {
                    ErrorKind::AlreadyExists => Error::AlreadyExists(path.to_path_buf()),
                    _ => Error::Io {
                        path: path.to_path_buf(),
                        source: error.error,
                    },
                })?;
        }
    }
    sync_directory(directory)
}

pub fn append_private(path: &Path, contents: &[u8]) -> Result<()> {
    private_options()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut file| file.write_all(contents))
        .at(path)
}

pub fn create_private_dir(path: &Path) -> Result<bool> {
    let existed = path.symlink_metadata().is_ok();
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(path).at(path)?;
    Ok(!existed)
}

pub fn create_private_subdir(path: &Path) -> Result<bool> {
    let created = create_private_dir(path)?;
    if is_real_directory(path) {
        Ok(created)
    } else {
        Err(refuse_link(path))
    }
}

#[must_use]
pub fn is_real_directory(path: &Path) -> bool {
    path.symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_dir())
}

fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let no_follow = i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits()).unwrap_or(0);
        options.mode(0o600).custom_flags(no_follow);
    }
    options
}

fn refuse_link(path: &Path) -> Error {
    Error::Io {
        path: path.to_path_buf(),
        source: io::Error::new(
            ErrorKind::InvalidInput,
            "refusing to follow a symbolic link or use a special file",
        ),
    }
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<()> {
    File::open(directory)
        .and_then(|handle| handle.sync_all())
        .at(directory)
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::TryLockError;

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn write_atomic_replaces_and_leaves_no_temporary_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("dev.vault");
        write_atomic(&path, b"first", WriteMode::Replace).unwrap();
        write_atomic(&path, b"second", WriteMode::Replace).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        #[cfg(unix)]
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn create_new_refuses_to_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("out.env");
        write_atomic(&path, b"original", WriteMode::CreateNew).unwrap();
        assert!(matches!(
            write_atomic(&path, b"other", WriteMode::CreateNew),
            Err(Error::AlreadyExists(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), b"original");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn read_bounded_handles_missing_and_oversized_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("file");
        assert!(read_bounded(&path, 4).unwrap().is_none());
        fs::write(&path, b"1234").unwrap();
        assert_eq!(read_bounded(&path, 4).unwrap().unwrap().as_slice(), b"1234");
        assert!(matches!(
            read_bounded(&path, 3),
            Err(Error::LimitExceeded(_))
        ));
    }

    #[test]
    fn append_private_appends_with_owner_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.log");
        append_private(&path, b"a\n").unwrap();
        append_private(&path, b"b\n").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"a\nb\n");
        #[cfg(unix)]
        assert_eq!(mode(&path), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_links_are_never_followed_when_writing() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("victim.txt");
        fs::write(&target, b"untouched").unwrap();
        let link = directory.path().join("audit.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(append_private(&link, b"injected\n").is_err());
        assert!(FileLock::acquire(&link, LockMode::Exclusive).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"untouched");
        assert!(read_bounded(directory.path(), 10).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn linked_subdirectories_are_refused() {
        let directory = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let link = directory.path().join("history");
        std::os::unix::fs::symlink(elsewhere.path(), &link).unwrap();
        assert!(create_private_subdir(&link).is_err());
        assert!(create_private_subdir(&directory.path().join("fresh")).unwrap());
        assert!(!create_private_subdir(&directory.path().join("fresh")).unwrap());
    }

    #[test]
    fn create_private_dir_reports_creation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nested").join(".shieldenv");
        assert!(create_private_dir(&path).unwrap());
        assert!(!create_private_dir(&path).unwrap());
        assert!(is_real_directory(&path));
        #[cfg(unix)]
        assert_eq!(mode(&path), 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_directories_are_not_real_directories() {
        let directory = tempfile::tempdir().unwrap();
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(directory.path(), &link).unwrap();
        assert!(!is_real_directory(&link));
    }

    #[test]
    fn exclusive_lock_excludes_other_holders() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("dev.lock");
        let probe = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .unwrap();
        {
            let _exclusive = FileLock::acquire(&path, LockMode::Exclusive).unwrap();
            assert!(matches!(
                probe.try_lock_shared(),
                Err(TryLockError::WouldBlock)
            ));
        }
        let _shared = FileLock::acquire(&path, LockMode::Shared).unwrap();
        assert!(probe.try_lock_shared().is_ok());
        probe.unlock().unwrap();
        assert!(matches!(probe.try_lock(), Err(TryLockError::WouldBlock)));
    }
}
