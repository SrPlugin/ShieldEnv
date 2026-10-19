#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;
use tempfile::TempDir;

const PASSWORD: &str = "correct horse battery";

struct Sandbox {
    root: TempDir,
}

impl Sandbox {
    fn new() -> Self {
        let sandbox = Self {
            root: tempfile::tempdir().unwrap(),
        };
        fs::create_dir_all(sandbox.project()).unwrap();
        fs::create_dir_all(sandbox.home()).unwrap();
        sandbox
    }

    fn initialized() -> Self {
        let sandbox = Self::new();
        sandbox.run(&["init"]).success();
        sandbox
    }

    fn with_secrets(entries: &[(&str, &str)]) -> Self {
        let sandbox = Self::initialized();
        for (key, value) in entries {
            sandbox.run(&["set", key, value]).success();
        }
        sandbox
    }

    fn project(&self) -> PathBuf {
        self.root.path().join("project")
    }

    fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }

    fn vault(&self, environment: &str) -> PathBuf {
        self.project()
            .join(".shieldenv")
            .join(format!("{environment}.vault"))
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_shieldenv"));
        command
            .current_dir(self.project())
            .env("HOME", self.home())
            .env("XDG_DATA_HOME", self.home().join("data"))
            .env("SHIELDENV_PASSWORD", PASSWORD)
            .env_remove("SHIELDENV_NEW_PASSWORD")
            .env_remove("SHIELDENV_ENV")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("SHIELDENV_IDENTITY")
            .env_remove("SHIELDENV_IDENTITY_FILE")
            .env_remove("SHIELDENV_IDENTITY_PASSPHRASE")
            .env("SHIELDENV_NO_KEYRING", "1");
        command
    }

    fn identity(&self, name: &str) -> (PathBuf, String) {
        let path = self.root.path().join(format!("{name}.key"));
        let created = self
            .command()
            .args(["id", "new", "--no-passphrase", "--file"])
            .arg(&path)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        (path, String::from_utf8(created).unwrap().trim().to_owned())
    }

    fn with_identity(&self, key_file: &Path) -> Command {
        let mut command = self.command();
        command.env("SHIELDENV_IDENTITY_FILE", key_file);
        command
    }

    fn as_member(&self, key_file: &Path) -> Command {
        let mut command = self.with_identity(key_file);
        command.env_remove("SHIELDENV_PASSWORD");
        command
    }

    fn run(&self, arguments: &[&str]) -> assert_cmd::assert::Assert {
        self.command().args(arguments).assert()
    }

    fn stdout(&self, arguments: &[&str]) -> String {
        let output = self.run(arguments).success().get_output().stdout.clone();
        String::from_utf8(output).unwrap()
    }
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn commands_outside_a_project_fail_like_git() {
    Sandbox::new()
        .run(&["ls"])
        .code(1)
        .stderr(contains("not a shieldenv project"));
}

#[test]
fn init_creates_private_directory() {
    let sandbox = Sandbox::new();
    sandbox
        .run(&["init"])
        .success()
        .stderr(contains("initialized empty shieldenv directory"));
    sandbox
        .run(&["init"])
        .success()
        .stderr(contains("already exists"));
    let directory = sandbox.project().join(".shieldenv");
    assert_eq!(
        fs::read_to_string(directory.join(".gitignore")).unwrap(),
        "*.lock\naudit.log\nhistory/\n"
    );
    #[cfg(unix)]
    assert_eq!(mode(&directory), 0o700);
}

#[test]
fn set_get_list_and_remove() {
    let sandbox = Sandbox::with_secrets(&[("B_KEY", "two"), ("A_KEY", "one")]);
    assert_eq!(sandbox.stdout(&["get", "A_KEY"]), "one\n");
    assert_eq!(sandbox.stdout(&["ls"]), "A_KEY\nB_KEY\n");
    sandbox
        .run(&["set", "A_KEY", "uno"])
        .success()
        .stderr(contains("updated A_KEY"));
    assert_eq!(sandbox.stdout(&["get", "A_KEY"]), "uno\n");
    sandbox.run(&["rm", "A_KEY", "B_KEY"]).success();
    assert_eq!(sandbox.stdout(&["ls"]), "");
    #[cfg(unix)]
    assert_eq!(mode(&sandbox.vault("dev")), 0o600);
}

#[test]
fn gen_stores_random_secrets_without_printing_them() {
    let sandbox = Sandbox::initialized();
    sandbox
        .run(&["gen", "JWT_SECRET", "-l", "48", "-c", "hex"])
        .success()
        .stdout("");
    let value = sandbox.stdout(&["get", "JWT_SECRET"]);
    let value = value.trim_end();
    assert_eq!(value.len(), 48);
    assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
    sandbox
        .run(&["gen", "JWT_SECRET"])
        .code(1)
        .stderr(contains("already exists"));
    sandbox.run(&["gen", "JWT_SECRET", "--force"]).success();
    assert_ne!(sandbox.stdout(&["get", "JWT_SECRET"]).trim_end(), value);
    sandbox.run(&["gen", "SHORT", "-l", "4"]).code(2);
    assert_eq!(sandbox.stdout(&["get", "JWT_SECRET"]).trim_end().len(), 32);
}

#[test]
fn mv_renames_keys_and_protects_existing_ones() {
    let sandbox = Sandbox::with_secrets(&[("OLD_NAME", "secret"), ("TAKEN", "other")]);
    sandbox.run(&["mv", "OLD_NAME", "NEW_NAME"]).success();
    assert_eq!(sandbox.stdout(&["ls"]), "NEW_NAME\nTAKEN\n");
    assert_eq!(sandbox.stdout(&["get", "NEW_NAME"]), "secret\n");
    sandbox
        .run(&["mv", "NEW_NAME", "TAKEN"])
        .code(1)
        .stderr(contains("already exists"));
    assert_eq!(sandbox.stdout(&["get", "TAKEN"]), "other\n");
    sandbox
        .run(&["mv", "NEW_NAME", "TAKEN", "--force"])
        .success();
    assert_eq!(sandbox.stdout(&["ls"]), "TAKEN\n");
    assert_eq!(sandbox.stdout(&["get", "TAKEN"]), "secret\n");
    sandbox.run(&["mv", "MISSING", "ANY"]).code(1);
    sandbox.run(&["mv", "TAKEN", "TAKEN"]).code(1);
}

#[test]
fn set_reads_value_from_stdin() {
    let sandbox = Sandbox::initialized();
    sandbox
        .command()
        .args(["set", "CERT"])
        .write_stdin("-----BEGIN-----\nbody\n")
        .assert()
        .success();
    assert_eq!(sandbox.stdout(&["get", "CERT"]), "-----BEGIN-----\nbody\n");
}

#[test]
fn missing_keys_are_reported_without_changes() {
    let sandbox = Sandbox::with_secrets(&[("KEEP", "1")]);
    sandbox
        .run(&["get", "NOPE"])
        .code(1)
        .stderr(contains("key 'NOPE' not found"));
    sandbox
        .run(&["rm", "KEEP", "NOPE"])
        .code(1)
        .stderr(contains("NOPE"));
    assert_eq!(sandbox.stdout(&["ls"]), "KEEP\n");
}

#[test]
fn invalid_keys_and_environments_are_usage_errors() {
    let sandbox = Sandbox::initialized();
    sandbox.run(&["set", "1BAD", "x"]).code(2);
    sandbox.run(&["set", "BAD-KEY", "x"]).code(2);
    for environment in ["../escape", "a/b", "..", "Prod"] {
        sandbox.run(&["-e", environment, "set", "KEY", "x"]).code(2);
    }
    let entries: Vec<_> = fs::read_dir(sandbox.project().join(".shieldenv"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries, [".gitignore"]);
    assert!(!sandbox.root.path().join("escape.vault").exists());
}

#[test]
fn weak_password_cannot_create_a_vault() {
    let sandbox = Sandbox::initialized();
    sandbox
        .command()
        .env("SHIELDENV_PASSWORD", "short")
        .args(["set", "KEY", "value"])
        .assert()
        .code(1)
        .stderr(contains("at least 12 characters"));
    assert!(!sandbox.vault("dev").exists());
}

#[test]
fn wrong_password_is_rejected() {
    let sandbox = Sandbox::with_secrets(&[("KEY", "value")]);
    sandbox
        .command()
        .env("SHIELDENV_PASSWORD", "not the password")
        .args(["get", "KEY"])
        .assert()
        .code(1)
        .stderr(contains("wrong password or tampered vault"))
        .stdout("");
}

#[test]
fn tampered_vault_fails_every_command() {
    let sandbox = Sandbox::with_secrets(&[("KEY", "value")]);
    let path = sandbox.vault("dev");
    let original = fs::read(&path).unwrap();
    for index in [0, 4, 5, 20, 60, 110, original.len() - 1] {
        let mut tampered = original.clone();
        tampered[index] ^= 0x01;
        fs::write(&path, &tampered).unwrap();
        sandbox.run(&["verify"]).code(1);
        sandbox.run(&["get", "KEY"]).code(1).stdout("");
    }
    fs::write(&path, &original).unwrap();
    sandbox
        .run(&["verify"])
        .success()
        .stderr(contains("intact"));
}

#[test]
fn import_merges_and_reports() {
    let sandbox = Sandbox::with_secrets(&[("EXISTING", "old")]);
    fs::write(
        sandbox.project().join(".env"),
        "# comment\nEXISTING=new\nexport FRESH=\"a b\"\nnot valid\n",
    )
    .unwrap();
    sandbox
        .run(&["import", ".env"])
        .success()
        .stderr(contains("1 added, 1 updated, 1 skipped").and(contains(".env:4")));
    assert_eq!(sandbox.stdout(&["get", "EXISTING"]), "new\n");
    assert_eq!(sandbox.stdout(&["get", "FRESH"]), "a b\n");
}

#[test]
fn export_round_trips_and_protects_files() {
    let sandbox = Sandbox::with_secrets(&[("PLAIN", "x"), ("QUOTED", "it's")]);
    assert_eq!(sandbox.stdout(&["export"]), "PLAIN='x'\nQUOTED=\"it's\"\n");
    let json: serde_json::Value =
        serde_json::from_str(&sandbox.stdout(&["export", "-f", "json"])).unwrap();
    assert_eq!(json["QUOTED"], "it's");
    sandbox.run(&["export", "-o", "out.env"]).success();
    sandbox
        .run(&["export", "-o", "out.env"])
        .code(1)
        .stderr(contains("already exists"));
    sandbox
        .run(&["export", "-o", "out.env", "--force"])
        .success();
    #[cfg(unix)]
    assert_eq!(mode(&sandbox.project().join("out.env")), 0o600);
    sandbox.run(&["-e", "copy", "import", "out.env"]).success();
    assert_eq!(sandbox.stdout(&["-e", "copy", "get", "QUOTED"]), "it's\n");
}

#[cfg(unix)]
#[test]
fn run_injects_secrets_without_any_credentials() {
    let sandbox = Sandbox::with_secrets(&[("API_KEY", "abc"), ("DB_URL", "db")]);
    sandbox
        .command()
        .env("SHIELDENV_NEW_PASSWORD", "should not leak")
        .env("SHIELDENV_IDENTITY", "shieldenv-secret1:should-not-leak")
        .env("SHIELDENV_IDENTITY_PASSPHRASE", "should not leak either")
        .args(["run", "--", "env"])
        .assert()
        .success()
        .stdout(
            contains("API_KEY=abc")
                .and(contains("DB_URL=db"))
                .and(contains("SHIELDENV_PASSWORD").not())
                .and(contains("SHIELDENV_NEW_PASSWORD").not())
                .and(contains("SHIELDENV_IDENTITY").not())
                .and(contains("should not leak").not()),
        );
}

#[cfg(unix)]
#[test]
fn run_only_injects_matching_keys() {
    let sandbox = Sandbox::with_secrets(&[("API_KEY", "abc"), ("DB_URL", "db")]);
    sandbox
        .run(&["run", "--only", "DB_*", "--", "env"])
        .success()
        .stdout(contains("DB_URL=db").and(contains("API_KEY").not()));
}

#[cfg(unix)]
#[test]
fn run_propagates_exit_codes() {
    let sandbox = Sandbox::with_secrets(&[("KEY", "value")]);
    sandbox.run(&["run", "--", "sh", "-c", "exit 7"]).code(7);
    sandbox
        .run(&["run", "--", "shieldenv-missing-program"])
        .code(127)
        .stderr(contains("cannot run"));
}

#[test]
fn diff_compares_key_names() {
    let sandbox = Sandbox::with_secrets(&[("SHARED", "1"), ("DEV_ONLY", "1")]);
    sandbox.run(&["-e", "prod", "set", "SHARED", "2"]).success();
    sandbox
        .run(&["-e", "prod", "set", "PROD_ONLY", "2"])
        .success();
    sandbox
        .run(&["diff", "dev", "prod"])
        .code(1)
        .stdout("- DEV_ONLY\n+ PROD_ONLY\n");
    sandbox.run(&["diff", "dev", "dev"]).success().stdout("");
}

#[test]
fn cp_copies_without_overwriting_unless_forced() {
    let sandbox = Sandbox::with_secrets(&[("A", "dev-a"), ("B", "dev-b")]);
    sandbox
        .run(&["-e", "staging", "set", "A", "staging-a"])
        .success();
    sandbox
        .run(&["cp", "--from", "dev", "--to", "staging"])
        .success()
        .stderr(contains("1 skipped"));
    assert_eq!(
        sandbox.stdout(&["-e", "staging", "get", "A"]),
        "staging-a\n"
    );
    assert_eq!(sandbox.stdout(&["-e", "staging", "get", "B"]), "dev-b\n");
    sandbox
        .run(&["cp", "--from", "dev", "--to", "staging", "--force"])
        .success();
    assert_eq!(sandbox.stdout(&["-e", "staging", "get", "A"]), "dev-a\n");
    sandbox
        .run(&["cp", "--from", "dev", "--to", "fresh"])
        .success()
        .stderr(contains("creating vault for 'fresh'"));
    assert_eq!(sandbox.stdout(&["-e", "fresh", "ls"]), "A\nB\n");
    sandbox.run(&["cp", "--from", "dev", "--to", "dev"]).code(1);
}

#[test]
fn passwd_rotates_the_password() {
    let sandbox = Sandbox::with_secrets(&[("KEY", "value")]);
    sandbox
        .command()
        .env("SHIELDENV_NEW_PASSWORD", "another long password")
        .arg("passwd")
        .assert()
        .success();
    sandbox.run(&["get", "KEY"]).code(1);
    sandbox
        .command()
        .env("SHIELDENV_PASSWORD", "another long password")
        .args(["get", "KEY"])
        .assert()
        .success()
        .stdout("value\n");
}

#[test]
fn shares_recover_access_after_a_password_change() {
    let sandbox = Sandbox::with_secrets(&[("KEY", "value")]);
    sandbox
        .run(&["shares", "split", "-n", "3", "-k", "2", "-o", "shares"])
        .success()
        .stdout(contains("share-3.txt"));
    sandbox
        .run(&["shares", "split", "-n", "3", "-k", "2", "-o", "shares"])
        .code(1)
        .stderr(contains("already exists"));
    #[cfg(unix)]
    assert_eq!(mode(&sandbox.project().join("shares/share-1.txt")), 0o600);
    sandbox
        .command()
        .env("SHIELDENV_NEW_PASSWORD", "forgotten password 1")
        .arg("passwd")
        .assert()
        .success();
    sandbox
        .run(&["shares", "recover", "shares/share-1.txt"])
        .code(2);
    sandbox
        .command()
        .env_remove("SHIELDENV_PASSWORD")
        .env("SHIELDENV_NEW_PASSWORD", "recovered password")
        .args([
            "shares",
            "recover",
            "shares/share-3.txt",
            "shares/share-1.txt",
        ])
        .assert()
        .success()
        .stdout("");
    sandbox
        .command()
        .env("SHIELDENV_PASSWORD", "recovered password")
        .args(["get", "KEY"])
        .assert()
        .success()
        .stdout("value\n");
}

#[test]
fn shares_from_another_vault_are_rejected() {
    let sandbox = Sandbox::with_secrets(&[("KEY", "value")]);
    sandbox.run(&["-e", "other", "set", "KEY", "x"]).success();
    sandbox
        .run(&[
            "-e", "other", "shares", "split", "-n", "2", "-k", "2", "-o", "other",
        ])
        .success();
    sandbox
        .command()
        .env("SHIELDENV_NEW_PASSWORD", "recovered password")
        .args([
            "shares",
            "recover",
            "other/share-1.txt",
            "other/share-2.txt",
        ])
        .assert()
        .code(1)
        .stderr(contains("do not unlock this vault"));
}

#[test]
fn status_env_and_log_describe_the_workspace() {
    let sandbox = Sandbox::with_secrets(&[("KEY", "value")]);
    sandbox.run(&["-e", "prod", "set", "KEY", "x"]).success();
    sandbox.run(&["status"]).success().stdout(
        contains("scope        project")
            .and(contains("keys         1"))
            .and(contains("argon2id m=65536 KiB t=3 p=4")),
    );
    assert_eq!(sandbox.stdout(&["-e", "prod", "env"]), "  dev\n* prod\n");
    let log = sandbox.stdout(&["log", "-n", "2"]);
    assert_eq!(log.lines().count(), 2);
    assert!(log.lines().next().unwrap().contains("status"));
    assert!(!log.contains("value"));
}

#[test]
fn global_scope_works_outside_projects() {
    let sandbox = Sandbox::new();
    sandbox.run(&["-g", "set", "TOKEN", "global"]).success();
    assert_eq!(sandbox.stdout(&["--global", "get", "TOKEN"]), "global\n");
    assert!(sandbox.home().join("data/shieldenv/dev.vault").is_file());
}

#[test]
fn environment_variable_selects_the_environment() {
    let sandbox = Sandbox::initialized();
    sandbox
        .command()
        .env("SHIELDENV_ENV", "staging")
        .args(["set", "KEY", "x"])
        .assert()
        .success();
    assert!(sandbox.vault("staging").is_file());
}

#[test]
fn completions_are_generated() {
    Sandbox::new()
        .run(&["completions", "bash"])
        .success()
        .stdout(contains("shieldenv"));
}

#[test]
fn scan_reports_plain_text_secrets_without_revealing_them() {
    let sandbox = Sandbox::new();
    sandbox
        .run(&["scan"])
        .success()
        .stderr(contains("no plain-text secrets"));
    fs::write(sandbox.project().join(".env"), "DB=postgres://x\n").unwrap();
    let token = format!("ghp_{}", "x1Y2".repeat(9));
    fs::write(sandbox.project().join("app.js"), format!("k = '{token}'\n")).unwrap();
    sandbox.run(&["scan"]).code(1).stdout(
        contains(".env: environment file")
            .and(contains("app.js:1: GitHub token"))
            .and(contains(token.as_str()).not())
            .and(contains("postgres").not()),
    );
}

#[test]
fn ls_long_and_stale_use_secret_timestamps() {
    let sandbox = Sandbox::with_secrets(&[("FRESH", "1")]);
    let long = sandbox.stdout(&["ls", "--long"]);
    let fields: Vec<_> = long.trim_end().split('\t').collect();
    assert_eq!(fields[0], "FRESH");
    assert_eq!(fields[1].len(), 10);
    assert_eq!(fields[2], "0d");
    assert_eq!(sandbox.stdout(&["ls", "--stale", "1"]), "");
    assert_eq!(sandbox.stdout(&["ls", "--stale", "0"]), "FRESH\n");
}

#[test]
fn rekey_keeps_secrets_but_invalidates_old_shares() {
    let sandbox = Sandbox::with_secrets(&[("KEY", "value")]);
    sandbox
        .run(&["shares", "split", "-n", "2", "-k", "2", "-o", "shares"])
        .success();
    sandbox
        .run(&["rekey"])
        .success()
        .stderr(contains("no longer work"));
    assert_eq!(sandbox.stdout(&["get", "KEY"]), "value\n");
    sandbox
        .run(&["status"])
        .success()
        .stdout(contains("generation   1"));
    sandbox
        .command()
        .env("SHIELDENV_NEW_PASSWORD", "recovered password")
        .args([
            "shares",
            "recover",
            "shares/share-1.txt",
            "shares/share-2.txt",
        ])
        .assert()
        .code(1)
        .stderr(contains("do not unlock this vault"));
}

#[test]
fn history_and_restore_undo_mistakes() {
    let sandbox = Sandbox::with_secrets(&[("KEEP", "important")]);
    sandbox.run(&["rm", "KEEP"]).success();
    assert_eq!(sandbox.stdout(&["ls"]), "");
    let history = sandbox.stdout(&["history"]);
    assert!(history.lines().count() >= 2);
    assert!(history.lines().next().unwrap().starts_with("1\t20"));
    sandbox
        .run(&["restore"])
        .success()
        .stderr(contains("restored 'dev'"));
    assert_eq!(sandbox.stdout(&["get", "KEEP"]), "important\n");
    sandbox
        .run(&["restore", "99"])
        .code(1)
        .stderr(contains("no such snapshot"));
    #[cfg(unix)]
    assert_eq!(
        mode(&sandbox.project().join(".shieldenv/history/dev")),
        0o700
    );
}

#[test]
fn rekey_discards_history() {
    let sandbox = Sandbox::with_secrets(&[("KEY", "value")]);
    assert!(!sandbox.stdout(&["history"]).is_empty());
    sandbox.run(&["rekey"]).success();
    assert_eq!(sandbox.stdout(&["history"]), "");
}

#[test]
fn identities_are_created_protected_and_shown() {
    let sandbox = Sandbox::new();
    let created = sandbox
        .command()
        .env("SHIELDENV_IDENTITY_PASSPHRASE", "identity passphrase")
        .args(["id", "new"])
        .assert()
        .success()
        .stderr(contains("fingerprint"))
        .get_output()
        .stdout
        .clone();
    let public = String::from_utf8(created).unwrap();
    assert!(public.starts_with("shieldenv-public1:age1"));
    let path = sandbox.home().join(".config/shieldenv/identity");
    let stored = fs::read(&path).unwrap();
    assert!(stored.starts_with(b"SHID"));
    #[cfg(unix)]
    assert_eq!(mode(&path), 0o600);
    assert_eq!(sandbox.stdout(&["id", "show"]), public);
    sandbox
        .command()
        .env("SHIELDENV_IDENTITY_PASSPHRASE", "identity passphrase")
        .args(["id", "new"])
        .assert()
        .code(1)
        .stderr(contains("already exists"));
}

#[test]
fn identity_passphrases_must_be_strong_and_plain_files_are_for_ci() {
    let sandbox = Sandbox::new();
    sandbox
        .command()
        .env("SHIELDENV_IDENTITY_PASSPHRASE", "short")
        .args(["id", "new"])
        .assert()
        .code(1)
        .stderr(contains("at least 12 characters"));
    assert!(!sandbox.home().join(".config/shieldenv/identity").exists());
    let ci_file = sandbox.root.path().join("ci.key");
    let created = sandbox
        .command()
        .args(["id", "new", "--no-passphrase", "--file"])
        .arg(&ci_file)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(
        fs::read_to_string(&ci_file)
            .unwrap()
            .starts_with("shieldenv-secret1:AGE-SECRET-KEY-1")
    );
    #[cfg(unix)]
    assert_eq!(mode(&ci_file), 0o600);
    let shown = sandbox
        .command()
        .env("SHIELDENV_IDENTITY_FILE", &ci_file)
        .args(["id", "show"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(shown, created);
}

#[test]
fn id_show_without_an_identity_explains_what_to_do() {
    Sandbox::new()
        .run(&["id", "show"])
        .code(1)
        .stderr(contains("shieldenv id new"));
}

struct Team {
    sandbox: Sandbox,
    alice: PathBuf,
    bob: PathBuf,
    bob_public: String,
}

fn team() -> Team {
    let sandbox = Sandbox::with_secrets(&[("API_KEY", "abc")]);
    let (alice, _) = sandbox.identity("alice");
    let (bob, bob_public) = sandbox.identity("bob");
    sandbox
        .with_identity(&alice)
        .args(["member", "init", "alice"])
        .assert()
        .success()
        .stderr(contains("administrator"));
    sandbox
        .with_identity(&alice)
        .args(["member", "add", "bob", &bob_public])
        .assert()
        .success();
    Team {
        sandbox,
        alice,
        bob,
        bob_public,
    }
}

#[test]
fn members_open_the_vault_with_their_identity_and_no_password() {
    let team = team();
    team.sandbox
        .as_member(&team.bob)
        .args(["get", "API_KEY"])
        .assert()
        .success()
        .stdout("abc\n");
    team.sandbox
        .as_member(&team.bob)
        .args(["set", "NEW_KEY", "written-by-bob"])
        .assert()
        .success();
    assert_eq!(team.sandbox.stdout(&["get", "NEW_KEY"]), "written-by-bob\n");
    let members = team.sandbox.stdout(&["member", "ls"]);
    assert!(members.contains("alice\tadmin\t"));
    assert!(members.contains("bob\tmember\t"));
}

#[test]
fn only_administrators_manage_members() {
    let team = team();
    let (_, carol_public) = team.sandbox.identity("carol");
    team.sandbox
        .as_member(&team.bob)
        .args(["member", "add", "carol", &carol_public])
        .assert()
        .code(1)
        .stderr(contains("only administrators"));
    team.sandbox
        .as_member(&team.bob)
        .args(["member", "rm", "alice"])
        .assert()
        .code(1)
        .stderr(contains("only administrators"));
    let (stranger, _) = team.sandbox.identity("stranger");
    team.sandbox
        .with_identity(&stranger)
        .args(["member", "add", "carol", &carol_public])
        .assert()
        .code(1)
        .stderr(contains("not a member"));
    team.sandbox
        .with_identity(&team.alice)
        .args(["member", "add", "bob", &team.bob_public])
        .assert()
        .code(1)
        .stderr(contains("already exists"));
    team.sandbox
        .with_identity(&team.alice)
        .args(["member", "init", "alice-again"])
        .assert()
        .code(1)
        .stderr(contains("already has members"));
}

#[test]
fn invalid_public_identities_are_usage_errors() {
    let team = team();
    team.sandbox
        .with_identity(&team.alice)
        .args(["member", "add", "carol", "not-an-identity"])
        .assert()
        .code(2);
    team.sandbox
        .with_identity(&team.alice)
        .args(["member", "add", "bad name", &team.bob_public])
        .assert()
        .code(2);
}

#[test]
fn removing_a_member_revokes_access_and_password() {
    let team = team();
    team.sandbox
        .with_identity(&team.alice)
        .args(["member", "rm", "bob"])
        .assert()
        .success()
        .stderr(contains("password access was removed too"));
    team.sandbox
        .as_member(&team.bob)
        .args(["get", "API_KEY"])
        .assert()
        .code(1)
        .stderr(contains("not a member"))
        .stdout("");
    team.sandbox
        .run(&["get", "API_KEY"])
        .code(1)
        .stderr(contains("cannot be opened with a password"));
    team.sandbox
        .as_member(&team.alice)
        .args(["get", "API_KEY"])
        .assert()
        .success()
        .stdout("abc\n");
    team.sandbox
        .as_member(&team.alice)
        .args(["member", "rm", "alice"])
        .assert()
        .code(1)
        .stderr(contains("cannot remove themselves"));
}

#[test]
fn rekey_keeps_member_access() {
    let team = team();
    team.sandbox
        .as_member(&team.alice)
        .arg("rekey")
        .assert()
        .success()
        .stderr(contains("password access was removed"));
    team.sandbox
        .as_member(&team.bob)
        .args(["get", "API_KEY"])
        .assert()
        .success()
        .stdout("abc\n");
    team.sandbox
        .as_member(&team.bob)
        .arg("status")
        .assert()
        .success()
        .stdout(contains("generation   1"));
}

#[test]
fn administrators_copy_member_lists_to_new_environments() {
    let team = team();
    team.sandbox
        .as_member(&team.alice)
        .args(["cp", "--from", "dev", "--to", "staging"])
        .assert()
        .success();
    team.sandbox
        .as_member(&team.bob)
        .args(["-e", "staging", "get", "API_KEY"])
        .assert()
        .success()
        .stdout("abc\n");
    team.sandbox
        .as_member(&team.bob)
        .args(["cp", "--from", "dev", "--to", "qa"])
        .assert()
        .code(1)
        .stderr(contains("cannot create a vault"));
}

#[test]
fn the_audit_log_names_the_actor() {
    let team = team();
    team.sandbox
        .as_member(&team.bob)
        .args(["get", "API_KEY"])
        .assert()
        .success();
    let log = team.sandbox.stdout(&["log", "-n", "1"]);
    assert!(log.contains("get"), "{log}");
    assert!(log.contains("bob"), "{log}");
    assert!(!log.contains("abc"));
    let by_password = team.sandbox.stdout(&["log", "-n", "50"]);
    assert!(by_password.contains("password"));
}

#[test]
fn encrypted_identities_ask_for_their_passphrase() {
    let sandbox = Sandbox::with_secrets(&[("API_KEY", "abc")]);
    sandbox
        .command()
        .env("SHIELDENV_IDENTITY_PASSPHRASE", "identity passphrase")
        .args(["id", "new"])
        .assert()
        .success();
    sandbox
        .command()
        .env("SHIELDENV_IDENTITY_PASSPHRASE", "identity passphrase")
        .args(["member", "init", "ana"])
        .assert()
        .success();
    sandbox
        .command()
        .env_remove("SHIELDENV_PASSWORD")
        .env("SHIELDENV_IDENTITY_PASSPHRASE", "identity passphrase")
        .args(["get", "API_KEY"])
        .assert()
        .success()
        .stdout("abc\n");
    sandbox
        .command()
        .env_remove("SHIELDENV_PASSWORD")
        .env("SHIELDENV_IDENTITY_PASSPHRASE", "not the passphrase!")
        .args(["get", "API_KEY"])
        .assert()
        .code(1)
        .stderr(contains("wrong password or tampered vault"));
}

#[test]
fn export_targets_docker_and_kubernetes() {
    let sandbox = Sandbox::with_secrets(&[("DB_URL", "postgres://x"), ("TOKEN", "a b")]);
    assert_eq!(
        sandbox.stdout(&["export", "-f", "docker"]),
        "DB_URL=postgres://x\nTOKEN=a b\n"
    );
    let manifest = sandbox.stdout(&["-e", "dev", "export", "-f", "k8s", "--namespace", "web"]);
    assert!(manifest.contains("kind: Secret"));
    assert!(manifest.contains("  name: dev\n  namespace: web"));
    assert!(manifest.contains("  DB_URL: cG9zdGdyZXM6Ly94"));
    assert!(!manifest.contains("postgres://x"));
    sandbox
        .run(&["export", "-f", "k8s", "--name", "Bad_Name"])
        .code(1);
    sandbox
        .run(&["export", "-f", "env", "--name", "x"])
        .code(1)
        .stderr(contains("only apply to the k8s format"));
    sandbox.run(&["set", "MULTI", "a\nb"]).success();
    sandbox
        .run(&["export", "-f", "docker"])
        .code(1)
        .stderr(contains("line breaks"));
}

#[cfg(unix)]
#[test]
fn run_file_delivers_secrets_as_files_not_variables() {
    let sandbox = Sandbox::with_secrets(&[
        ("TLS_CERT", "-----BEGIN-----\nbody\n-----END-----"),
        ("API_KEY", "key-value"),
    ]);
    sandbox
        .run(&[
            "run",
            "--file",
            "CERT_PATH=TLS_CERT",
            "--",
            "sh",
            "-c",
            "cat \"$CERT_PATH\"; echo; echo \"cert=${TLS_CERT:-unset} key=$API_KEY\"",
        ])
        .success()
        .stdout(
            contains("-----BEGIN-----\nbody\n-----END-----")
                .and(contains("cert=unset key=key-value")),
        );
    sandbox
        .run(&["run", "--file", "PATH_VAR=MISSING", "--", "true"])
        .code(1)
        .stderr(contains("key 'MISSING' not found"));
    sandbox
        .run(&["run", "--file", "NOEQUALS", "--", "true"])
        .code(2);
    sandbox
        .run(&[
            "run",
            "--file",
            "CERT_PATH=TLS_CERT",
            "--",
            "sh",
            "-c",
            "exit 9",
        ])
        .code(9);
}

fn git_available() -> bool {
    std::process::Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn git(sandbox: &Sandbox, arguments: &[&str]) -> std::process::Output {
    std::process::Command::new("git")
        .current_dir(sandbox.project())
        .args(["-c", "user.name=Test", "-c", "user.email=test@example.com"])
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(arguments)
        .env("HOME", sandbox.home())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("SHIELDENV_PASSWORD", PASSWORD)
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap()
}

#[test]
fn git_merges_vault_files_key_by_key() {
    if !git_available() {
        return;
    }
    let sandbox = Sandbox::with_secrets(&[("SHARED", "1")]);
    assert!(git(&sandbox, &["init", "-q"]).status.success());
    sandbox
        .run(&["git-setup"])
        .success()
        .stderr(contains("key by key"));
    sandbox.run(&["git-setup"]).success();
    let attributes = fs::read_to_string(sandbox.project().join(".gitattributes")).unwrap();
    assert_eq!(attributes.matches("merge=shieldenv").count(), 1);
    assert!(git(&sandbox, &["add", "-A"]).status.success());
    assert!(git(&sandbox, &["commit", "-qm", "base"]).status.success());
    assert!(
        git(&sandbox, &["checkout", "-qb", "feature"])
            .status
            .success()
    );
    sandbox.run(&["set", "FROM_FEATURE", "f"]).success();
    assert!(
        git(&sandbox, &["commit", "-qam", "feature"])
            .status
            .success()
    );
    assert!(git(&sandbox, &["checkout", "-q", "main"]).status.success());
    sandbox.run(&["set", "FROM_MAIN", "m"]).success();
    assert!(git(&sandbox, &["commit", "-qam", "main"]).status.success());
    let merge = git(&sandbox, &["merge", "-q", "feature", "-m", "merge"]);
    assert!(
        merge.status.success(),
        "{}{}",
        String::from_utf8_lossy(&merge.stdout),
        String::from_utf8_lossy(&merge.stderr)
    );
    assert_eq!(sandbox.stdout(&["ls"]), "FROM_FEATURE\nFROM_MAIN\nSHARED\n");
    sandbox.run(&["verify"]).success();
}

#[test]
fn git_reports_conflicting_secrets_without_leaking_them() {
    if !git_available() {
        return;
    }
    let sandbox = Sandbox::with_secrets(&[("TOKEN", "base-value")]);
    assert!(git(&sandbox, &["init", "-q"]).status.success());
    sandbox.run(&["git-setup"]).success();
    assert!(git(&sandbox, &["add", "-A"]).status.success());
    assert!(git(&sandbox, &["commit", "-qm", "base"]).status.success());
    assert!(
        git(&sandbox, &["checkout", "-qb", "feature"])
            .status
            .success()
    );
    sandbox.run(&["set", "TOKEN", "feature-secret"]).success();
    assert!(
        git(&sandbox, &["commit", "-qam", "feature"])
            .status
            .success()
    );
    assert!(git(&sandbox, &["checkout", "-q", "main"]).status.success());
    sandbox.run(&["set", "TOKEN", "main-secret"]).success();
    assert!(git(&sandbox, &["commit", "-qam", "main"]).status.success());
    let merge = git(&sandbox, &["merge", "-q", "feature", "-m", "merge"]);
    assert!(!merge.status.success());
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&merge.stdout),
        String::from_utf8_lossy(&merge.stderr)
    );
    assert!(output.contains("TOKEN"), "{output}");
    assert!(!output.contains("feature-secret") && !output.contains("main-secret"));
}

#[test]
fn git_setup_requires_a_repository() {
    if !git_available() {
        return;
    }
    let sandbox = Sandbox::new();
    sandbox
        .command()
        .current_dir(sandbox.home())
        .env("GIT_CEILING_DIRECTORIES", sandbox.root.path())
        .arg("git-setup")
        .assert()
        .code(1)
        .stderr(contains("not a git repository"));
}

#[test]
fn rolled_back_vaults_are_refused_until_accepted() {
    let team = team();
    let path = team.sandbox.vault("dev");
    let old_version = fs::read(&path).unwrap();
    team.sandbox
        .as_member(&team.alice)
        .arg("rekey")
        .assert()
        .success();
    team.sandbox
        .as_member(&team.alice)
        .args(["get", "API_KEY"])
        .assert()
        .success();
    fs::write(&path, old_version).unwrap();
    team.sandbox
        .as_member(&team.alice)
        .args(["get", "API_KEY"])
        .assert()
        .code(1)
        .stderr(contains("rollback").and(contains("trust accept")))
        .stdout("");
    team.sandbox
        .as_member(&team.alice)
        .args(["trust", "accept"])
        .assert()
        .success();
    team.sandbox
        .as_member(&team.alice)
        .args(["get", "API_KEY"])
        .assert()
        .success()
        .stdout("abc\n");
}

#[test]
fn unseen_administrator_changes_need_approval() {
    let team = team();
    let machine = |sandbox: &Sandbox, key: &Path, name: &str| {
        let mut command = sandbox.as_member(key);
        command.env("XDG_DATA_HOME", sandbox.home().join(format!("data-{name}")));
        command
    };
    machine(&team.sandbox, &team.bob, "bob")
        .args(["get", "API_KEY"])
        .assert()
        .success()
        .stderr(contains("trusting these administrators"));
    let (carol, carol_public) = team.sandbox.identity("carol");
    team.sandbox
        .as_member(&team.alice)
        .args(["member", "add", "carol", &carol_public, "--admin"])
        .assert()
        .success();
    machine(&team.sandbox, &carol, "carol")
        .args(["member", "rm", "alice"])
        .assert()
        .success();
    machine(&team.sandbox, &team.bob, "bob")
        .args(["get", "API_KEY"])
        .assert()
        .code(1)
        .stderr(
            contains("signed by carol").and(contains("who is not an administrator you trusted")),
        )
        .stdout("");
    machine(&team.sandbox, &team.bob, "bob")
        .args(["trust", "accept"])
        .assert()
        .success()
        .stderr(contains("carol"));
    machine(&team.sandbox, &team.bob, "bob")
        .args(["get", "API_KEY"])
        .assert()
        .success()
        .stdout("abc\n");
}

#[test]
fn trust_accept_on_a_password_vault_is_a_no_op() {
    let sandbox = Sandbox::with_secrets(&[("KEY", "value")]);
    sandbox
        .run(&["trust", "accept"])
        .success()
        .stderr(contains("no members"));
}

#[cfg(unix)]
#[test]
fn run_withholds_variables_that_change_how_code_is_loaded() {
    let sandbox = Sandbox::with_secrets(&[
        ("API_KEY", "abc"),
        ("LD_PRELOAD", "/tmp/evil.so"),
        ("NODE_OPTIONS", "--require evil"),
    ]);
    sandbox
        .run(&["run", "--", "env"])
        .success()
        .stdout(
            contains("API_KEY=abc")
                .and(contains("LD_PRELOAD").not())
                .and(contains("NODE_OPTIONS").not()),
        )
        .stderr(contains("not injecting LD_PRELOAD, NODE_OPTIONS"));
    sandbox
        .run(&[
            "run",
            "--allow-process-hooks",
            "--",
            "sh",
            "-c",
            "echo $NODE_OPTIONS",
        ])
        .success()
        .stdout(contains("--require evil"));
}

#[test]
fn only_administrators_can_rekey_a_vault_with_members() {
    let team = team();
    team.sandbox
        .as_member(&team.bob)
        .arg("rekey")
        .assert()
        .code(1)
        .stderr(contains("only administrators"));
    team.sandbox.run(&["rekey"]).code(1).stderr(
        contains("no identity")
            .or(contains("not a member"))
            .or(contains("only administrators")),
    );
    team.sandbox
        .as_member(&team.bob)
        .args(["get", "API_KEY"])
        .assert()
        .success();
}

#[cfg(unix)]
#[test]
fn scan_does_not_forward_control_characters_from_file_names() {
    let sandbox = Sandbox::new();
    fs::write(sandbox.project().join(".env.\u{1b}[31mred"), "A=1").unwrap();
    let output = sandbox.run(&["scan"]).code(1).get_output().stdout.clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("environment file"));
    assert!(!text.contains('\u{1b}'));
}
