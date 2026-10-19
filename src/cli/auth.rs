use std::cell::RefCell;

use secrecy::SecretString;
use shieldenv::crypto::{Identity, Inspection, Unlock};
use shieldenv::storage::keystore::{self, Located, Sources};
use shieldenv::storage::{Outcome, TrustStore};
use shieldenv::{Error, Result};

use super::output::notice;
use super::prompt::Prompter;

const PASSWORD_ACTOR: &str = "password";

#[derive(Debug, Default)]
pub(super) struct Credentials {
    pub(super) password: Option<SecretString>,
    pub(super) identity: Option<Identity>,
}

impl Credentials {
    pub(super) fn as_unlock(&self) -> Option<Unlock<'_>> {
        match (&self.identity, &self.password) {
            (Some(identity), _) => Some(Unlock::Identity(identity)),
            (None, Some(password)) => Some(Unlock::Password(password)),
            (None, None) => None,
        }
    }
}

pub(super) struct Authenticator {
    pub(super) prompter: Prompter,
    identities: Sources,
    trust: Option<TrustStore>,
    actor: RefCell<Option<String>>,
}

impl Authenticator {
    pub(super) fn new() -> Self {
        Self {
            prompter: Prompter::from_environment(),
            identities: Sources::from_environment(),
            trust: TrustStore::default_path().map(TrustStore::new),
            actor: RefCell::new(None),
        }
    }

    pub(super) fn authenticate<T>(
        &self,
        label: &str,
        inspection: &Inspection,
        mut open: impl FnMut(Unlock<'_>) -> Result<T>,
    ) -> Result<(T, Credentials)> {
        self.check_trust(inspection)?;
        if let Some(identity) = self.member_identity(inspection)? {
            let opened = open(Unlock::Identity(&identity))?;
            self.set_actor(actor_name(inspection, &identity));
            return Ok((
                opened,
                Credentials {
                    password: None,
                    identity: Some(identity),
                },
            ));
        }
        if !inspection.has_password {
            return Err(if keystore::locate(&self.identities)?.is_some() {
                Error::NotAMember
            } else {
                Error::NoPasswordAccess
            });
        }
        let (opened, password) = self
            .prompter
            .unlock(label, |password| open(Unlock::Password(password)))?;
        self.set_actor(PASSWORD_ACTOR.to_owned());
        Ok((
            opened,
            Credentials {
                password: Some(password),
                identity: None,
            },
        ))
    }

    pub(super) fn check_trust(&self, inspection: &Inspection) -> Result<()> {
        let Some(store) = &self.trust else {
            return if inspection.members.is_empty() {
                Ok(())
            } else {
                Err(Error::NoDataDirectory)
            };
        };
        match store.check(inspection)? {
            Outcome::FirstUse => notice(format!(
                "trusting these administrators for this vault from now on: {}",
                administrators(inspection)
            )),
            Outcome::Advanced => notice(format!(
                "the administrators of this vault changed; now trusting: {}",
                administrators(inspection)
            )),
            Outcome::NoMembers | Outcome::Unchanged => {}
        }
        Ok(())
    }

    pub(super) fn accept_trust(&self, inspection: &Inspection) -> Result<bool> {
        if inspection.members.is_empty() {
            return Ok(false);
        }
        let store = self.trust.as_ref().ok_or(Error::NoDataDirectory)?;
        store.record(inspection)?;
        notice(format!(
            "trusting these administrators for this vault: {}",
            administrators(inspection)
        ));
        Ok(true)
    }

    pub(super) fn active_identity(&self) -> Result<Identity> {
        let located = keystore::locate(&self.identities)?.ok_or(Error::NoIdentity)?;
        self.unlock_identity(located)
    }

    pub(super) fn identity_for(&self, credentials: Credentials) -> Result<Identity> {
        match credentials.identity {
            Some(identity) => Ok(identity),
            None => self.active_identity(),
        }
    }

    pub(super) fn actor(&self) -> Option<String> {
        self.actor.borrow().clone()
    }

    fn member_identity(&self, inspection: &Inspection) -> Result<Option<Identity>> {
        if inspection.members.is_empty() {
            return Ok(None);
        }
        let Some(located) = keystore::locate(&self.identities)? else {
            return Ok(None);
        };
        let is_member = inspection
            .members
            .iter()
            .any(|member| member.public == *located.public());
        if is_member {
            self.unlock_identity(located).map(Some)
        } else {
            Ok(None)
        }
    }

    fn unlock_identity(&self, located: Located) -> Result<Identity> {
        let mut remaining = self.prompter.identity_attempts();
        let mut candidate = Some(located);
        loop {
            let current = match candidate.take() {
                Some(located) => located,
                None => keystore::locate(&self.identities)?.ok_or(Error::NoIdentity)?,
            };
            match current.unlock(|| self.prompter.identity_passphrase()) {
                Err(Error::Authentication) if remaining > 1 => {
                    remaining -= 1;
                    notice("wrong passphrase, try again");
                }
                result => return result,
            }
        }
    }

    fn set_actor(&self, actor: String) {
        *self.actor.borrow_mut() = Some(actor);
    }
}

fn administrators(inspection: &Inspection) -> String {
    inspection
        .members
        .iter()
        .filter(|member| member.admin)
        .map(|member| format!("{} ({})", member.name, member.public.fingerprint()))
        .collect::<Vec<_>>()
        .join(", ")
}

fn actor_name(inspection: &Inspection, identity: &Identity) -> String {
    let public = identity.public();
    inspection
        .members
        .iter()
        .find(|member| member.public == public)
        .map_or_else(|| public.fingerprint(), |member| member.name.to_string())
}
