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
            .env_remove("SHIELDENV_ENV");
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
        "*.lock\naudit.log\n"
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
fn run_injects_secrets_without_the_password() {
    let sandbox = Sandbox::with_secrets(&[("API_KEY", "abc"), ("DB_URL", "db")]);
    sandbox
        .command()
        .env("SHIELDENV_NEW_PASSWORD", "should not leak")
        .args(["run", "--", "env"])
        .assert()
        .success()
        .stdout(
            contains("API_KEY=abc")
                .and(contains("DB_URL=db"))
                .and(contains("SHIELDENV_PASSWORD").not())
                .and(contains("SHIELDENV_NEW_PASSWORD").not()),
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
