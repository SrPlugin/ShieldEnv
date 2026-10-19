use std::io::{self, IsTerminal, Read};

use secrecy::{ExposeSecret, SecretString};
use shieldenv::domain::{Environment, SecretKey, SecretValue, Secrets};
use shieldenv::{Error, Result};
use zeroize::Zeroizing;

pub const PASSWORD_VARIABLE: &str = "SHIELDENV_PASSWORD";
pub const NEW_PASSWORD_VARIABLE: &str = "SHIELDENV_NEW_PASSWORD";
pub const IDENTITY_PASSPHRASE_VARIABLE: &str = "SHIELDENV_IDENTITY_PASSPHRASE";

const MIN_PASSWORD_LEN: usize = 12;
const INTERACTIVE_ATTEMPTS: usize = 3;

#[derive(Debug)]
pub struct Prompter {
    password: Option<SecretString>,
    new_password: Option<SecretString>,
    identity_passphrase: Option<SecretString>,
}

impl Prompter {
    pub fn from_environment() -> Self {
        Self {
            password: variable(PASSWORD_VARIABLE),
            new_password: variable(NEW_PASSWORD_VARIABLE),
            identity_passphrase: variable(IDENTITY_PASSPHRASE_VARIABLE),
        }
    }

    pub fn unlock<T>(
        &self,
        label: &str,
        mut attempt: impl FnMut(&SecretString) -> Result<T>,
    ) -> Result<(T, SecretString)> {
        if let Some(password) = &self.password {
            return attempt(password).map(|value| (value, password.clone()));
        }
        let mut remaining = INTERACTIVE_ATTEMPTS;
        loop {
            let password = ask(&format!("Password for '{label}': "))?;
            match attempt(&password) {
                Err(Error::Authentication) if remaining > 1 => {
                    remaining -= 1;
                    eprintln!("wrong password, try again");
                }
                result => return result.map(|value| (value, password)),
            }
        }
    }

    pub fn initial_password(&self, environment: &Environment) -> Result<SecretString> {
        match &self.password {
            Some(password) => validated(password.clone()),
            None => confirmed(environment),
        }
    }

    pub fn identity_passphrase(&self) -> Result<SecretString> {
        match &self.identity_passphrase {
            Some(passphrase) => Ok(passphrase.clone()),
            None => ask("Passphrase for your identity: "),
        }
    }

    #[must_use]
    pub fn identity_attempts(&self) -> usize {
        if self.identity_passphrase.is_some() {
            1
        } else {
            INTERACTIVE_ATTEMPTS
        }
    }

    pub fn new_identity_passphrase(&self) -> Result<SecretString> {
        match &self.identity_passphrase {
            Some(passphrase) => validated(passphrase.clone()),
            None => confirmed_with("New identity passphrase: "),
        }
    }

    pub fn replacement_password(&self, environment: &Environment) -> Result<SecretString> {
        match &self.new_password {
            Some(password) => validated(password.clone()),
            None => confirmed(environment),
        }
    }
}

pub fn value(key: &SecretKey) -> Result<SecretValue> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return rpassword::prompt_password(format!("Value for {key}: "))
            .map(Zeroizing::new)
            .map_err(Error::Terminal);
    }
    let limit = Secrets::MAX_VALUE_LEN + 2;
    let mut bytes = Zeroizing::new(Vec::with_capacity(64 * 1024));
    stdin
        .lock()
        .take(u64::try_from(limit).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(Error::Terminal)?;
    if bytes.len() >= limit {
        return Err(Error::LimitExceeded("secret value larger than 1 MiB"));
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| Error::InvalidValue("stdin is not UTF-8"))?;
    let text = text
        .strip_suffix('\n')
        .map_or(text, |line| line.strip_suffix('\r').unwrap_or(line));
    Ok(Zeroizing::new(text.to_owned()))
}

fn variable(name: &str) -> Option<SecretString> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .map(SecretString::from)
}

fn ask(prompt: &str) -> Result<SecretString> {
    rpassword::prompt_password(prompt)
        .map(SecretString::from)
        .map_err(Error::Terminal)
}

fn confirmed(environment: &Environment) -> Result<SecretString> {
    confirmed_with(&format!("New password for '{environment}': "))
}

fn confirmed_with(prompt: &str) -> Result<SecretString> {
    let password = validated(ask(prompt)?)?;
    let confirmation = ask("Confirm password: ")?;
    if password.expose_secret() == confirmation.expose_secret() {
        Ok(password)
    } else {
        Err(Error::PasswordMismatch)
    }
}

fn validated(password: SecretString) -> Result<SecretString> {
    if password.expose_secret().chars().count() >= MIN_PASSWORD_LEN {
        Ok(password)
    } else {
        Err(Error::WeakPassword(MIN_PASSWORD_LEN))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prompter(password: Option<&str>, new_password: Option<&str>) -> Prompter {
        Prompter {
            password: password.map(|text| SecretString::from(text.to_owned())),
            new_password: new_password.map(|text| SecretString::from(text.to_owned())),
            identity_passphrase: None,
        }
    }

    #[test]
    fn non_interactive_passwords_are_validated() {
        let dev = Environment::default();
        assert!(matches!(
            prompter(Some("short"), None).initial_password(&dev),
            Err(Error::WeakPassword(MIN_PASSWORD_LEN))
        ));
        assert!(
            prompter(Some("long enough pw"), None)
                .initial_password(&dev)
                .is_ok()
        );
        assert!(matches!(
            prompter(None, Some("short")).replacement_password(&dev),
            Err(Error::WeakPassword(_))
        ));
        assert!(
            prompter(None, Some("contraseña larga"))
                .replacement_password(&dev)
                .is_ok()
        );
    }

    #[test]
    fn non_interactive_unlock_tries_once() {
        let mut calls = 0;
        let result = prompter(Some("any password"), None).unlock("dev", |_| {
            calls += 1;
            Err::<(), _>(Error::Authentication)
        });
        assert!(matches!(result, Err(Error::Authentication)));
        assert_eq!(calls, 1);
    }
}
