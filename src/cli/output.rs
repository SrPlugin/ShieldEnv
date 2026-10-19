use std::fmt::Display;
use std::io::{self, Write};

use shieldenv::{Error, Result};

pub(super) fn format_date(seconds: u64) -> String {
    let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(seconds);
    let stamp = humantime::format_rfc3339_seconds(time).to_string();
    stamp.get(..10).unwrap_or(&stamp).to_owned()
}

pub(super) fn plural(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("1 {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

pub(super) fn notice(message: impl Display) {
    eprintln!("{message}");
}

pub(super) fn write_stdout(bytes: &[u8]) -> Result<()> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(bytes)
        .and_then(|()| stdout.flush())
        .map_err(Error::Terminal)
}

pub(super) fn printable(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() {
                '?'
            } else {
                character
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_never_reach_the_terminal() {
        assert_eq!(printable("a\x1b[31mred\n\0b"), "a?[31mred??b");
        assert_eq!(printable("plain-ñame.env"), "plain-ñame.env");
    }
}
