pub mod args;
mod auth;
pub mod commands;
mod context;
mod git;
pub mod hardening;
mod identity;
mod members;
mod output;
pub mod prompt;

use std::io::ErrorKind;

use shieldenv::Error;

#[must_use]
pub fn exit_code(error: &Error) -> u8 {
    match error {
        Error::Spawn { source, .. } if source.kind() == ErrorKind::NotFound => 127,
        Error::Spawn { .. } => 126,
        _ => 1,
    }
}
