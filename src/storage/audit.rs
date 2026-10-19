use std::fs::File;
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde_json::{Value, json};

use super::file::append_private;
use crate::domain::Environment;
use crate::{IoContext, Result};

const TAIL_BYTES: u64 = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub timestamp: String,
    pub action: String,
    pub environment: String,
    pub keys: Vec<String>,
    pub ok: bool,
    pub actor: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn record(
        &self,
        action: &str,
        environment: &Environment,
        keys: &[&str],
        ok: bool,
        actor: Option<&str>,
    ) -> Result<()> {
        let timestamp = humantime::format_rfc3339_seconds(SystemTime::now()).to_string();
        let mut line = json!({
            "ts": timestamp,
            "action": action,
            "env": environment.as_str(),
            "keys": keys,
            "ok": ok,
            "by": actor,
        })
        .to_string();
        line.push('\n');
        append_private(&self.path, line.as_bytes())
    }

    pub fn recent(&self, limit: usize) -> Result<Vec<AuditEntry>> {
        let tail = read_tail(&self.path)?;
        Ok(tail
            .lines()
            .rev()
            .filter_map(parse_entry)
            .take(limit)
            .collect())
    }
}

fn read_tail(path: &Path) -> Result<String> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => return Err(error).at(path),
    };
    let length = file.metadata().at(path)?.len();
    let offset = length.saturating_sub(TAIL_BYTES);
    file.seek(SeekFrom::Start(offset)).at(path)?;
    let mut bytes = Vec::new();
    file.take(TAIL_BYTES).read_to_end(&mut bytes).at(path)?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    if offset == 0 {
        return Ok(text);
    }
    Ok(text
        .split_once('\n')
        .map(|(_, complete)| complete.to_owned())
        .unwrap_or_default())
}

fn parse_entry(line: &str) -> Option<AuditEntry> {
    let value: Value = serde_json::from_str(line).ok()?;
    let text = |field: &str| value.get(field)?.as_str().map(printable);
    Some(AuditEntry {
        timestamp: text("ts")?,
        action: text("action")?,
        environment: text("env")?,
        keys: value
            .get("keys")?
            .as_array()?
            .iter()
            .filter_map(Value::as_str)
            .map(printable)
            .collect(),
        ok: value.get("ok")?.as_bool()?,
        actor: value.get("by").and_then(Value::as_str).map(printable),
    })
}

fn printable(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_control())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn log() -> (tempfile::TempDir, AuditLog) {
        let directory = tempfile::tempdir().unwrap();
        let log = AuditLog::new(directory.path().join("audit.log"));
        (directory, log)
    }

    #[test]
    fn missing_log_is_empty() {
        let (_directory, log) = log();
        assert!(log.recent(10).unwrap().is_empty());
    }

    #[test]
    fn records_are_returned_newest_first() {
        let (_directory, log) = log();
        let dev: Environment = "dev".parse().unwrap();
        log.record("set", &dev, &["API_KEY"], true, Some("ana"))
            .unwrap();
        log.record("get", &dev, &[], false, None).unwrap();
        let entries = log.recent(10).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].action, "get");
        assert!(!entries[0].ok);
        assert_eq!(entries[1].action, "set");
        assert_eq!(entries[1].keys, ["API_KEY"]);
        assert_eq!(entries[1].environment, "dev");
        assert_eq!(entries[1].actor.as_deref(), Some("ana"));
        assert_eq!(entries[0].actor, None);
        assert!(entries[1].timestamp.ends_with('Z'));
        assert_eq!(log.recent(1).unwrap().len(), 1);
    }

    #[test]
    fn malformed_lines_and_control_characters_are_neutralized() {
        let (directory, log) = log();
        fs::write(
            directory.path().join("audit.log"),
            "garbage\n{\"ts\":\"t\",\"action\":\"set\\u001b[31m\",\"env\":\"dev\",\"keys\":[\"A\\n\"],\"ok\":true}\n",
        )
        .unwrap();
        let entries = log.recent(10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "set[31m");
        assert_eq!(entries[0].keys, ["A"]);
    }

    #[test]
    fn large_logs_are_read_from_the_tail() {
        let (directory, log) = log();
        let filler = "x".repeat(usize::try_from(TAIL_BYTES).unwrap());
        fs::write(directory.path().join("audit.log"), format!("{filler}\n")).unwrap();
        log.record("rm", &"dev".parse().unwrap(), &["OLD"], true, None)
            .unwrap();
        let entries = log.recent(10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "rm");
    }
}
