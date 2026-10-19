use std::ffi::OsString;
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{self, ExitCode};

use clap::CommandFactory;
use clap_complete::Shell;
use shieldenv::app::{
    Access, Charset, Vault, parse_dotenv, random_secret, render, render_kubernetes, scan,
};
use shieldenv::crypto::{KEY_LEN, Key, shamir};
use shieldenv::domain::{Environment, Pattern, SecretKey, unix_now};
use shieldenv::storage::file::{WriteMode, create_private_dir, read_bounded, write_atomic};
use shieldenv::storage::secretfile::{DeliveredFile, deliver};
use shieldenv::storage::{AuditLog, History, Scope, Workspace};
use shieldenv::{Error, Result};
use zeroize::Zeroizing;

use super::args::{Cli, Command, ExportFormat, FileDelivery, MemberCommand, SharesCommand};
use super::context::Context;
use super::git;
use super::identity::manage_identity;
use super::output::{format_date, notice, plural, write_stdout};
use super::prompt::{self, NEW_PASSWORD_VARIABLE, PASSWORD_VARIABLE};

const IMPORT_LIMIT: usize = 16 << 20;
const SHARE_LIMIT: usize = 8 * 1024;
const SHARE_PREFIX: &str = "share-";
const SHARE_SUFFIX: &str = ".txt";
const SECONDS_PER_DAY: u64 = 86_400;

pub fn execute(cli: Cli) -> Result<ExitCode> {
    let Cli {
        env: environment,
        global,
        command,
    } = cli;
    let scope = if global {
        Scope::Global
    } else {
        Scope::Project
    };
    let working_directory = std::env::current_dir().map_err(Error::Terminal)?;
    match command {
        Command::Init => init(scope, &working_directory),
        Command::Completions { shell } => completions(shell),
        Command::Scan { path } => scan_for_secrets(&path),
        Command::Id { action } => manage_identity(action),
        Command::GitSetup => git::setup(&working_directory),
        Command::Merge { base, ours, theirs } => git::merge(&base, &ours, &theirs),
        command => Context::new(Workspace::locate(scope, &working_directory)?, environment)
            .dispatch(command),
    }
}

fn init(scope: Scope, working_directory: &Path) -> Result<ExitCode> {
    let (workspace, created) = Workspace::init(scope, working_directory)?;
    let directory = workspace.directory().display();
    if created {
        notice(format!(
            "initialized empty shieldenv directory in {directory}"
        ));
    } else {
        notice(format!("shieldenv directory already exists in {directory}"));
    }
    Ok(ExitCode::SUCCESS)
}

fn scan_for_secrets(path: &Path) -> Result<ExitCode> {
    let findings = scan(path)?;
    let mut output = String::new();
    for finding in &findings {
        let location = finding
            .line
            .map_or_else(String::new, |line| format!(":{line}"));
        let _ = writeln!(
            output,
            "{}{location}: {}",
            finding.path.display(),
            finding.kind
        );
    }
    write_stdout(output.as_bytes())?;
    if findings.is_empty() {
        notice("no plain-text secrets found");
        Ok(ExitCode::SUCCESS)
    } else {
        notice(format!(
            "{} found; move them into a vault with 'shieldenv import' and delete the originals",
            plural(findings.len(), "finding")
        ));
        Ok(ExitCode::FAILURE)
    }
}

fn completions(shell: Shell) -> Result<ExitCode> {
    let mut output = Vec::new();
    clap_complete::generate(shell, &mut Cli::command(), "shieldenv", &mut output);
    write_stdout(&output)?;
    Ok(ExitCode::SUCCESS)
}

impl Context {
    fn dispatch(&self, command: Command) -> Result<ExitCode> {
        match command {
            Command::Set { key, value } => {
                self.audited("set", &[key.as_str()], || self.set(&key, value))
            }
            Command::Gen {
                key,
                length,
                charset,
                force,
            } => self.audited("gen", &[key.as_str()], || {
                self.generate(&key, usize::from(length), charset.into(), force)
            }),
            Command::Mv { old, new, force } => {
                self.audited("mv", &[old.as_str(), new.as_str()], || {
                    self.rename(&old, &new, force)
                })
            }
            Command::Get { key } => self.audited("get", &[key.as_str()], || self.get(&key)),
            Command::Rm { keys } => {
                let names: Vec<&str> = keys.iter().map(SecretKey::as_str).collect();
                self.audited("rm", &names, || self.remove(&keys))
            }
            Command::Ls { long, stale } => self.audited("ls", &[], || self.list(long, stale)),
            Command::Import { file } => self.audited("import", &[], || self.import(&file)),
            Command::Export {
                format,
                output,
                force,
                name,
                namespace,
            } => self.audited("export", &[], || {
                self.export(
                    format,
                    output.as_deref(),
                    force,
                    name.as_deref(),
                    namespace.as_deref(),
                )
            }),
            Command::Run {
                only,
                files,
                command,
            } => {
                let (prepared, deliveries) =
                    self.audited("run", &[], || self.prepare_run(&only, &files, command))?;
                launch(prepared, &deliveries)
            }
            Command::Diff { left, right } => {
                let result = self.diff(&left, &right);
                self.record(&left, "diff", &[], result.is_ok());
                result
            }
            Command::Cp { from, to, force } => self.copy(&from, &to, force),
            Command::Passwd => self.audited("passwd", &[], || self.change_password()),
            Command::Rekey => self.audited("rekey", &[], || self.rekey()),
            Command::History => self.audited("history", &[], || self.history()),
            Command::Restore { snapshot } => {
                self.audited("restore", &[], || self.restore(snapshot))
            }
            Command::Status => self.audited("status", &[], || self.status()),
            Command::Verify => self.audited("verify", &[], || self.verify()),
            Command::Env => self.environments(),
            Command::Shares { action } => match action {
                SharesCommand::Split {
                    shares,
                    threshold,
                    output,
                } => self.audited("shares-split", &[], || {
                    self.split_shares(shares, threshold, &output)
                }),
                SharesCommand::Recover { files } => {
                    self.audited("shares-recover", &[], || self.recover(&files))
                }
            },
            Command::Member { action } => match action {
                MemberCommand::Init { name } => {
                    self.audited("member-init", &[name.as_str()], || self.member_init(&name))
                }
                MemberCommand::Add {
                    name,
                    public,
                    admin,
                } => self.audited("member-add", &[name.as_str()], || {
                    self.member_add(&name, *public, admin)
                }),
                MemberCommand::Rm { name } => {
                    self.audited("member-rm", &[name.as_str()], || self.member_remove(&name))
                }
                MemberCommand::Ls => self.member_list(),
            },
            Command::Log { count } => self.log(count),
            Command::Init
            | Command::Completions { .. }
            | Command::Scan { .. }
            | Command::GitSetup
            | Command::Merge { .. }
            | Command::Id { .. } => Ok(ExitCode::SUCCESS),
        }
    }

    fn set(&self, key: &SecretKey, value: Option<String>) -> Result<ExitCode> {
        let value = match value {
            Some(value) => Zeroizing::new(value),
            None => prompt::value(key)?,
        };
        let mut vault = self.open_or_create(&self.environment)?;
        let replaced = vault.secrets_mut().insert(key.clone(), value)?;
        vault.save()?;
        let verb = if replaced { "updated" } else { "added" };
        notice(format!("{verb} {key} in '{}'", self.environment));
        Ok(ExitCode::SUCCESS)
    }

    fn generate(
        &self,
        key: &SecretKey,
        length: usize,
        charset: Charset,
        force: bool,
    ) -> Result<ExitCode> {
        let value = random_secret(charset, length)?;
        let mut vault = self.open_or_create(&self.environment)?;
        if vault.secrets().contains(key.as_str()) && !force {
            return Err(Error::KeyExists(key.to_string()));
        }
        vault.secrets_mut().insert(key.clone(), value)?;
        vault.save()?;
        notice(format!(
            "generated {key} ({length} characters) in '{}'",
            self.environment
        ));
        Ok(ExitCode::SUCCESS)
    }

    fn rename(&self, old: &SecretKey, new: &SecretKey, force: bool) -> Result<ExitCode> {
        if old == new {
            return Err(Error::InvalidValue("source and target keys are identical"));
        }
        let mut vault = self.open(&self.environment, Access::Write)?;
        if vault.secrets().contains(new.as_str()) && !force {
            return Err(Error::KeyExists(new.to_string()));
        }
        vault.secrets_mut().rename(old.as_str(), new.clone())?;
        vault.save()?;
        notice(format!("renamed {old} to {new} in '{}'", self.environment));
        Ok(ExitCode::SUCCESS)
    }

    fn get(&self, key: &SecretKey) -> Result<ExitCode> {
        let vault = self.open(&self.environment, Access::Read)?;
        let value = vault
            .secrets()
            .get(key.as_str())
            .ok_or_else(|| Error::KeyNotFound(key.to_string()))?;
        let mut line = Zeroizing::new(String::with_capacity(value.len() + 1));
        line.push_str(value);
        line.push('\n');
        write_stdout(line.as_bytes())?;
        Ok(ExitCode::SUCCESS)
    }

    fn remove(&self, keys: &[SecretKey]) -> Result<ExitCode> {
        let mut vault = self.open(&self.environment, Access::Write)?;
        if let Some(missing) = keys
            .iter()
            .find(|key| !vault.secrets().contains(key.as_str()))
        {
            return Err(Error::KeyNotFound(missing.to_string()));
        }
        for key in keys {
            vault.secrets_mut().remove(key.as_str());
        }
        vault.save()?;
        notice(format!(
            "removed {} from '{}'",
            plural(keys.len(), "secret"),
            self.environment
        ));
        Ok(ExitCode::SUCCESS)
    }

    fn list(&self, long: bool, stale: Option<u32>) -> Result<ExitCode> {
        let vault = self.open(&self.environment, Access::Read)?;
        let now = unix_now();
        let cutoff = stale.map_or(u64::MAX, |days| {
            now.saturating_sub(u64::from(days) * SECONDS_PER_DAY)
        });
        let mut output = String::new();
        for (key, meta) in vault.secrets().updated_before(cutoff) {
            if long {
                let age = now.saturating_sub(meta.updated) / SECONDS_PER_DAY;
                let _ = writeln!(output, "{key}\t{}\t{age}d", format_date(meta.updated));
            } else {
                let _ = writeln!(output, "{key}");
            }
        }
        write_stdout(output.as_bytes())?;
        Ok(ExitCode::SUCCESS)
    }

    fn import(&self, file: &Path) -> Result<ExitCode> {
        let bytes = read_bounded(file, IMPORT_LIMIT)?.ok_or_else(|| Error::Io {
            path: file.to_path_buf(),
            source: io::ErrorKind::NotFound.into(),
        })?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| Error::InvalidValue("import file is not UTF-8"))?;
        let parsed = parse_dotenv(text);
        let mut vault = self.open_or_create(&self.environment)?;
        let (mut added, mut updated) = (0, 0);
        for (key, value) in parsed.entries {
            if vault.secrets_mut().insert(key, value)? {
                updated += 1;
            } else {
                added += 1;
            }
        }
        vault.save()?;
        for line in &parsed.rejected_lines {
            notice(format!(
                "skipped {}:{line}: not a valid assignment",
                file.display()
            ));
        }
        notice(format!(
            "imported into '{}': {added} added, {updated} updated, {} skipped",
            self.environment,
            parsed.rejected_lines.len()
        ));
        Ok(ExitCode::SUCCESS)
    }

    fn export(
        &self,
        format: ExportFormat,
        output: Option<&Path>,
        force: bool,
        name: Option<&str>,
        namespace: Option<&str>,
    ) -> Result<ExitCode> {
        if format != ExportFormat::K8s && (name.is_some() || namespace.is_some()) {
            return Err(Error::InvalidValue(
                "--name and --namespace only apply to the k8s format",
            ));
        }
        let vault = self.open(&self.environment, Access::Read)?;
        let rendered = if let Some(plain) = format.plain_format() {
            render(vault.secrets(), plain)?
        } else {
            let default_name = self.environment.as_str().replace('_', "-");
            render_kubernetes(vault.secrets(), name.unwrap_or(&default_name), namespace)?
        };
        match output {
            Some(path) => {
                let mode = if force {
                    WriteMode::Replace
                } else {
                    WriteMode::CreateNew
                };
                write_atomic(path, &rendered, mode)?;
                notice(format!(
                    "exported {} to {}",
                    plural(vault.secrets().len(), "secret"),
                    path.display()
                ));
            }
            None => write_stdout(&rendered)?,
        }
        Ok(ExitCode::SUCCESS)
    }

    fn prepare_run(
        &self,
        only: &[Pattern],
        files: &[FileDelivery],
        argv: Vec<OsString>,
    ) -> Result<(process::Command, Vec<DeliveredFile>)> {
        let mut arguments = argv.into_iter();
        let program = arguments
            .next()
            .ok_or(Error::InvalidValue("missing command to run"))?;
        let vault = self.open(&self.environment, Access::Read)?;
        let mut command = process::Command::new(&program);
        command
            .args(arguments)
            .env_remove(PASSWORD_VARIABLE)
            .env_remove(NEW_PASSWORD_VARIABLE);
        let delivered_keys: Vec<&SecretKey> = files.iter().map(|file| &file.key).collect();
        for (key, value) in vault.secrets().iter() {
            let selected = only.is_empty() || only.iter().any(|pattern| pattern.matches(key));
            if selected && !delivered_keys.contains(&key) {
                command.env(key.as_str(), value);
            }
        }
        let mut deliveries = Vec::with_capacity(files.len());
        for file in files {
            let value = vault
                .secrets()
                .get(file.key.as_str())
                .ok_or_else(|| Error::KeyNotFound(file.key.to_string()))?;
            let delivered = deliver(file.variable.as_str(), value)?;
            command.env(file.variable.as_str(), delivered.path());
            deliveries.push(delivered);
        }
        Ok((command, deliveries))
    }

    fn diff(&self, left: &Environment, right: &Environment) -> Result<ExitCode> {
        let (left_vault, credentials) = self.unlock(left, Access::Read)?;
        let right_vault = self.open_reusing(right, Access::Read, &credentials)?;
        let mut output = String::new();
        for key in left_vault.secrets().keys() {
            if !right_vault.secrets().contains(key.as_str()) {
                let _ = writeln!(output, "- {key}");
            }
        }
        for key in right_vault.secrets().keys() {
            if !left_vault.secrets().contains(key.as_str()) {
                let _ = writeln!(output, "+ {key}");
            }
        }
        write_stdout(output.as_bytes())?;
        Ok(if output.is_empty() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        })
    }

    fn copy(&self, from: &Environment, to: &Environment, force: bool) -> Result<ExitCode> {
        if from == to {
            return Err(Error::SameEnvironment);
        }
        let result = self.copy_secrets(from, to, force);
        self.record(to, "cp", &[], result.is_ok());
        result
    }

    fn copy_secrets(&self, from: &Environment, to: &Environment, force: bool) -> Result<ExitCode> {
        let (source, credentials) = self.unlock(from, Access::Read)?;
        let mut target = if Vault::exists(&self.workspace, to) {
            self.open_reusing(to, Access::Write, &credentials)?
        } else {
            notice(format!("creating vault for '{to}'"));
            source.create_sibling(
                &self.workspace,
                to,
                credentials.password.as_ref(),
                credentials.identity.as_ref(),
            )?
        };
        let (mut copied, mut skipped) = (0, 0);
        for (key, value) in source.secrets().iter() {
            if !force && target.secrets().contains(key.as_str()) {
                skipped += 1;
            } else {
                target
                    .secrets_mut()
                    .insert(key.clone(), Zeroizing::new(value.to_owned()))?;
                copied += 1;
            }
        }
        target.save()?;
        notice(format!(
            "copied {} from '{from}' to '{to}', {skipped} skipped",
            plural(copied, "secret")
        ));
        Ok(ExitCode::SUCCESS)
    }

    fn change_password(&self) -> Result<ExitCode> {
        let mut vault = self.open(&self.environment, Access::Write)?;
        let password = self.prompter().replacement_password(&self.environment)?;
        vault.change_password(&password)?;
        notice(format!("password changed for '{}'", self.environment));
        Ok(ExitCode::SUCCESS)
    }

    fn rekey(&self) -> Result<ExitCode> {
        let (mut vault, credentials) = self.unlock(&self.environment, Access::Write)?;
        let dropped_password = vault.rekey(credentials.password.as_ref())?;
        notice(format!(
            "rotated the data key of '{}'; earlier recovery shares no longer work, \
             and secrets seen by former members should be changed",
            self.environment
        ));
        if dropped_password {
            notice(
                "password access was removed because the vault was not opened with it; \
                 set one again with 'shieldenv passwd'",
            );
        }
        Ok(ExitCode::SUCCESS)
    }

    fn history(&self) -> Result<ExitCode> {
        let history = History::new(self.workspace.history_path(&self.environment));
        let snapshots = history.list()?;
        if snapshots.is_empty() {
            notice(format!("no saved states for '{}' yet", self.environment));
        }
        let mut output = String::new();
        for (index, snapshot) in snapshots.iter().enumerate() {
            let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(snapshot.taken);
            let _ = writeln!(
                output,
                "{}\t{}\t{} bytes",
                index + 1,
                humantime::format_rfc3339_seconds(time),
                snapshot.size
            );
        }
        write_stdout(output.as_bytes())?;
        Ok(ExitCode::SUCCESS)
    }

    fn restore(&self, snapshot: usize) -> Result<ExitCode> {
        let mut vault = self.open(&self.environment, Access::Write)?;
        vault.restore(snapshot)?;
        notice(format!(
            "restored '{}' to saved state {snapshot}; the previous state is now state 1",
            self.environment
        ));
        Ok(ExitCode::SUCCESS)
    }

    fn status(&self) -> Result<ExitCode> {
        let vault = self.open(&self.environment, Access::Read)?;
        let metadata = vault.path().metadata().map_err(|source| Error::Io {
            path: vault.path().to_path_buf(),
            source,
        })?;
        let modified = metadata.modified().map_or_else(
            |_| "unknown".to_owned(),
            |time| humantime::format_rfc3339_seconds(time).to_string(),
        );
        let kdf = vault.params().map_or_else(
            || "none".to_owned(),
            |params| {
                format!(
                    "argon2id m={} KiB t={} p={}",
                    params.memory_kib, params.iterations, params.parallelism
                )
            },
        );
        let members = vault.members();
        let administrators = members.iter().filter(|member| member.admin).count();
        let access = match (vault.has_password(), members.len()) {
            (true, 0) => "password".to_owned(),
            (true, count) => format!(
                "password and {} ({administrators} administrators)",
                plural(count, "member")
            ),
            (false, count) => format!(
                "{} ({administrators} administrators)",
                plural(count, "member")
            ),
        };
        let report = format!(
            "vault        {}\nscope        {}\nenvironment  {}\nkeys         {}\nsize         {} bytes\nmodified     {modified}\ngeneration   {}\naccess       {access}\nkdf          {kdf}\ncipher       xchacha20-poly1305\n",
            vault.path().display(),
            self.workspace.scope(),
            vault.environment(),
            vault.secrets().len(),
            metadata.len(),
            vault.generation(),
        );
        write_stdout(report.as_bytes())?;
        Ok(ExitCode::SUCCESS)
    }

    fn verify(&self) -> Result<ExitCode> {
        let vault = self.open(&self.environment, Access::Read)?;
        notice(format!(
            "vault '{}' is intact ({})",
            self.environment,
            plural(vault.secrets().len(), "secret")
        ));
        Ok(ExitCode::SUCCESS)
    }

    fn environments(&self) -> Result<ExitCode> {
        let environments = self.workspace.environments()?;
        if environments.is_empty() {
            notice("no vaults yet; create one with 'shieldenv set <KEY>'");
        }
        let mut output = String::new();
        for environment in &environments {
            let marker = if *environment == self.environment {
                '*'
            } else {
                ' '
            };
            let _ = writeln!(output, "{marker} {environment}");
        }
        write_stdout(output.as_bytes())?;
        Ok(ExitCode::SUCCESS)
    }

    fn split_shares(&self, count: u8, threshold: u8, directory: &Path) -> Result<ExitCode> {
        create_private_dir(directory)?;
        let existing = directory.join(share_file_name(1));
        if existing.exists() {
            return Err(Error::AlreadyExists(existing));
        }
        let vault = self.open(&self.environment, Access::Read)?;
        let shares = shamir::split(vault.data_key().as_slice(), threshold, count)?;
        let mut written = String::new();
        for share in &shares {
            let path = directory.join(share_file_name(share.index()));
            let mut contents = share.encode();
            contents.push('\n');
            write_atomic(&path, contents.as_bytes(), WriteMode::CreateNew)?;
            let _ = writeln!(written, "{}", path.display());
        }
        write_stdout(written.as_bytes())?;
        notice(format!(
            "any {threshold} of these {count} shares recover '{}'; store them in separate places",
            self.environment
        ));
        Ok(ExitCode::SUCCESS)
    }

    fn recover(&self, files: &[PathBuf]) -> Result<ExitCode> {
        let mut shares = Vec::with_capacity(files.len());
        for file in files {
            let bytes = read_bounded(file, SHARE_LIMIT)?.ok_or_else(|| Error::Io {
                path: file.clone(),
                source: io::ErrorKind::NotFound.into(),
            })?;
            let text =
                std::str::from_utf8(&bytes).map_err(|_| Error::Shares("share is not UTF-8"))?;
            shares.push(shamir::Share::decode(text)?);
        }
        let secret = shamir::combine(&shares)?;
        let data_key: Key = Zeroizing::new(
            <[u8; KEY_LEN]>::try_from(secret.as_slice())
                .map_err(|_| Error::Shares("shares do not contain a vault key"))?,
        );
        let mut vault =
            Vault::open_with_key(&self.workspace, &self.environment, data_key, Access::Write)
                .map_err(|error| match error {
                    Error::Authentication => Error::Shares("shares do not unlock this vault"),
                    other => other,
                })?;
        let password = self.prompter().replacement_password(&self.environment)?;
        vault.change_password(&password)?;
        notice(format!(
            "access to '{}' recovered with a new password",
            self.environment
        ));
        Ok(ExitCode::SUCCESS)
    }

    fn log(&self, count: usize) -> Result<ExitCode> {
        let entries = AuditLog::new(self.workspace.audit_path()).recent(count)?;
        let mut output = String::new();
        for entry in &entries {
            let _ = writeln!(
                output,
                "{}  {:<14} {:<12} {:<6} {:<10} {}",
                entry.timestamp,
                entry.action,
                entry.environment,
                if entry.ok { "ok" } else { "failed" },
                entry.actor.as_deref().unwrap_or("-"),
                entry.keys.join(" ")
            );
        }
        write_stdout(output.as_bytes())?;
        Ok(ExitCode::SUCCESS)
    }
}

#[cfg(unix)]
fn launch(mut command: process::Command, deliveries: &[DeliveredFile]) -> Result<ExitCode> {
    use std::os::unix::process::CommandExt;
    if deliveries.iter().all(DeliveredFile::survives_exec) {
        let program = command.get_program().to_string_lossy().into_owned();
        let source = command.exec();
        return Err(Error::Spawn { program, source });
    }
    run_to_completion(&mut command)
}

#[cfg(not(unix))]
fn launch(mut command: process::Command, _deliveries: &[DeliveredFile]) -> Result<ExitCode> {
    run_to_completion(&mut command)
}

fn run_to_completion(command: &mut process::Command) -> Result<ExitCode> {
    let program = command.get_program().to_string_lossy().into_owned();
    let status = command
        .status()
        .map_err(|source| Error::Spawn { program, source })?;
    Ok(exit_code(status))
}

#[cfg(unix)]
fn exit_code(status: process::ExitStatus) -> ExitCode {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .and_then(|code| u8::try_from(code).ok())
        .map_or(ExitCode::FAILURE, ExitCode::from)
}

#[cfg(not(unix))]
fn exit_code(status: process::ExitStatus) -> ExitCode {
    status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .map_or(ExitCode::FAILURE, ExitCode::from)
}

fn share_file_name(index: u8) -> String {
    format!("{SHARE_PREFIX}{index}{SHARE_SUFFIX}")
}
