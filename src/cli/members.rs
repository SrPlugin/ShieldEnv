use std::fmt::Write as _;
use std::process::ExitCode;

use shieldenv::Result;
use shieldenv::app::Access;
use shieldenv::crypto::PublicIdentity;
use shieldenv::domain::MemberName;

use super::context::Context;
use super::output::{notice, plural, write_stdout};

impl Context {
    pub(super) fn member_init(&self, name: &MemberName) -> Result<ExitCode> {
        let (mut vault, _) = self.unlock(&self.environment, Access::Write)?;
        let identity = self.active_identity()?;
        vault.init_admin(&identity, name.clone())?;
        notice(format!(
            "{name} is now the administrator of '{}'",
            self.environment
        ));
        Ok(ExitCode::SUCCESS)
    }

    pub(super) fn member_add(
        &self,
        name: &MemberName,
        public: PublicIdentity,
        admin: bool,
    ) -> Result<ExitCode> {
        let (mut vault, credentials) = self.unlock(&self.environment, Access::Write)?;
        let identity = self.identity_for(credentials)?;
        let fingerprint = public.fingerprint();
        vault.add_member(&identity, name.clone(), public, admin)?;
        let role = if admin { "administrator" } else { "member" };
        notice(format!(
            "added {name} as {role} of '{}' (fingerprint {fingerprint})",
            self.environment
        ));
        Ok(ExitCode::SUCCESS)
    }

    pub(super) fn member_remove(&self, name: &MemberName) -> Result<ExitCode> {
        let (mut vault, credentials) = self.unlock(&self.environment, Access::Write)?;
        let identity = self.identity_for(credentials)?;
        let had_password = vault.has_password();
        vault.remove_member(&identity, name, None)?;
        notice(format!(
            "removed {name} from '{}' and rotated its data key; change the secrets they could read",
            self.environment
        ));
        if had_password {
            notice(
                "password access was removed too, because the former member may know it; \
                 set a new one with 'shieldenv passwd'",
            );
        }
        Ok(ExitCode::SUCCESS)
    }

    pub(super) fn member_list(&self) -> Result<ExitCode> {
        let inspection = self.trusted_inspection(&self.environment)?;
        if inspection.members.is_empty() {
            notice(format!(
                "'{}' has no members; it is protected by its password only",
                self.environment
            ));
        }
        let mut output = String::new();
        for member in &inspection.members {
            let role = if member.admin { "admin" } else { "member" };
            let _ = writeln!(
                output,
                "{}\t{role}\t{}",
                member.name,
                member.public.fingerprint()
            );
        }
        write_stdout(output.as_bytes())?;
        if inspection.has_password && !inspection.members.is_empty() {
            notice(format!(
                "password access is also enabled ({})",
                plural(inspection.members.len(), "member")
            ));
        }
        Ok(ExitCode::SUCCESS)
    }
}

impl Context {
    pub(super) fn trust_accept(&self) -> Result<ExitCode> {
        if !self.accept_trust()? {
            notice(format!(
                "'{}' has no members, so there is nothing to trust",
                self.environment
            ));
        }
        Ok(ExitCode::SUCCESS)
    }
}
