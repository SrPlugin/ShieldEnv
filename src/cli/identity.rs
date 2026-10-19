use std::process::ExitCode;

use shieldenv::crypto::{Identity, identity_file};
use shieldenv::storage::keystore::{self, Sources};
use shieldenv::{Error, Result};
use zeroize::Zeroizing;

use super::args::IdCommand;
use super::output::{notice, write_stdout};
use super::prompt::Prompter;

pub(super) fn manage_identity(action: IdCommand) -> Result<ExitCode> {
    match action {
        IdCommand::New {
            file,
            no_passphrase,
        } => {
            let path = file
                .or_else(keystore::default_path)
                .ok_or(Error::NoDataDirectory)?;
            if path.exists() {
                return Err(Error::AlreadyExists(path));
            }
            let identity = Identity::generate()?;
            let contents = if no_passphrase {
                let mut text = identity.secret_text();
                text.push('\n');
                Zeroizing::new(text.as_bytes().to_vec())
            } else {
                let passphrase = Prompter::from_environment().new_identity_passphrase()?;
                Zeroizing::new(identity_file::seal(&identity, &passphrase)?)
            };
            keystore::create(&path, &contents)?;
            let public = identity.public();
            notice(format!(
                "identity saved to {} (fingerprint {}); give the line below to an administrator",
                path.display(),
                public.fingerprint()
            ));
            write_stdout(format!("{public}\n").as_bytes())?;
        }
        IdCommand::Show => {
            let located =
                keystore::locate(&Sources::from_environment())?.ok_or(Error::NoIdentity)?;
            notice(format!("fingerprint {}", located.public().fingerprint()));
            write_stdout(format!("{}\n", located.public()).as_bytes())?;
        }
    }
    Ok(ExitCode::SUCCESS)
}
