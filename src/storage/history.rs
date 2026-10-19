use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use super::file::{WriteMode, create_private_dir, read_bounded, write_atomic};
use crate::crypto::MAX_VAULT_LEN;
use crate::{Error, IoContext, Result};

pub const LIMIT: usize = 10;

const EXTENSION: &str = ".vault";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub path: PathBuf,
    pub taken: u64,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct History {
    directory: PathBuf,
}

impl History {
    #[must_use]
    pub fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    pub fn record(&self, current: &Path) -> Result<()> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        self.record_at(current, elapsed)
    }

    pub fn record_at(&self, current: &Path, taken: Duration) -> Result<()> {
        let Some(contents) = read_bounded(current, MAX_VAULT_LEN)? else {
            return Ok(());
        };
        create_private_dir(&self.directory)?;
        let name = format!(
            "{:012}-{:09}{EXTENSION}",
            taken.as_secs(),
            taken.subsec_nanos()
        );
        write_atomic(&self.directory.join(name), &contents, WriteMode::CreateNew)?;
        self.prune()
    }

    pub fn list(&self) -> Result<Vec<Snapshot>> {
        let entries = match fs::read_dir(&self.directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error).at(&self.directory),
        };
        let mut snapshots: Vec<Snapshot> = entries
            .filter_map(std::result::Result::ok)
            .filter_map(|entry| {
                let taken = parse_name(entry.file_name().to_str()?)?;
                let metadata = entry.metadata().ok().filter(fs::Metadata::is_file)?;
                Some(Snapshot {
                    path: entry.path(),
                    taken,
                    size: metadata.len(),
                })
            })
            .collect();
        snapshots.sort_by(|left, right| right.path.cmp(&left.path));
        Ok(snapshots)
    }

    pub fn read(&self, number: usize) -> Result<Zeroizing<Vec<u8>>> {
        let snapshots = self.list()?;
        let snapshot = number
            .checked_sub(1)
            .and_then(|index| snapshots.get(index))
            .ok_or(Error::InvalidValue(
                "no such snapshot; see 'shieldenv history'",
            ))?;
        read_bounded(&snapshot.path, MAX_VAULT_LEN)?
            .ok_or(Error::InvalidValue("snapshot disappeared"))
    }

    pub fn clear(&self) -> Result<()> {
        for snapshot in self.list()? {
            fs::remove_file(&snapshot.path).at(&snapshot.path)?;
        }
        Ok(())
    }

    fn prune(&self) -> Result<()> {
        for snapshot in self.list()?.into_iter().skip(LIMIT) {
            fs::remove_file(&snapshot.path).at(&snapshot.path)?;
        }
        Ok(())
    }
}

fn parse_name(name: &str) -> Option<u64> {
    let stem = name.strip_suffix(EXTENSION)?;
    let (seconds, nanos) = stem.split_once('-')?;
    let well_formed = seconds.len() == 12
        && nanos.len() == 9
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'-');
    well_formed.then(|| seconds.parse().ok()).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _root: tempfile::TempDir,
        current: PathBuf,
        history: History,
    }

    fn fixture() -> Fixture {
        let root = tempfile::tempdir().unwrap();
        Fixture {
            current: root.path().join("dev.vault"),
            history: History::new(root.path().join("history").join("dev")),
            _root: root,
        }
    }

    fn snapshot(fixture: &Fixture, contents: &[u8], second: u64) {
        fs::write(&fixture.current, contents).unwrap();
        fixture
            .history
            .record_at(&fixture.current, Duration::from_secs(second))
            .unwrap();
    }

    #[test]
    fn recording_without_a_vault_does_nothing() {
        let fixture = fixture();
        fixture.history.record(&fixture.current).unwrap();
        assert!(fixture.history.list().unwrap().is_empty());
        assert!(!fixture.history.directory.exists());
    }

    #[test]
    fn snapshots_are_listed_newest_first_and_readable() {
        let fixture = fixture();
        snapshot(&fixture, b"first", 100);
        snapshot(&fixture, b"second", 200);
        snapshot(&fixture, b"third", 300);
        let listed = fixture.history.list().unwrap();
        let taken: Vec<_> = listed.iter().map(|snapshot| snapshot.taken).collect();
        assert_eq!(taken, [300, 200, 100]);
        assert_eq!(listed[0].size, 5);
        assert_eq!(fixture.history.read(1).unwrap().as_slice(), b"third");
        assert_eq!(fixture.history.read(3).unwrap().as_slice(), b"first");
        assert!(fixture.history.read(0).is_err());
        assert!(fixture.history.read(4).is_err());
    }

    #[test]
    fn only_the_most_recent_snapshots_are_kept() {
        let fixture = fixture();
        for second in 1..=u64::try_from(LIMIT + 5).unwrap() {
            snapshot(&fixture, second.to_string().as_bytes(), second);
        }
        let listed = fixture.history.list().unwrap();
        assert_eq!(listed.len(), LIMIT);
        assert_eq!(listed[0].taken, u64::try_from(LIMIT + 5).unwrap());
        assert_eq!(listed[LIMIT - 1].taken, 6);
    }

    #[test]
    fn unrelated_files_are_ignored_and_clear_removes_snapshots() {
        let fixture = fixture();
        snapshot(&fixture, b"data", 10);
        fs::write(fixture.history.directory.join("notes.txt"), b"x").unwrap();
        fs::write(fixture.history.directory.join("1-2.vault"), b"x").unwrap();
        assert_eq!(fixture.history.list().unwrap().len(), 1);
        fixture.history.clear().unwrap();
        assert!(fixture.history.list().unwrap().is_empty());
        assert!(fixture.history.directory.join("notes.txt").exists());
    }

    #[test]
    fn repeated_timestamps_never_overwrite() {
        let fixture = fixture();
        snapshot(&fixture, b"one", 50);
        fs::write(&fixture.current, b"two").unwrap();
        assert!(matches!(
            fixture
                .history
                .record_at(&fixture.current, Duration::from_secs(50)),
            Err(Error::AlreadyExists(_))
        ));
        assert_eq!(fixture.history.read(1).unwrap().as_slice(), b"one");
    }
}
