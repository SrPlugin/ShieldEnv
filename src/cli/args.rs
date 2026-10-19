use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use shieldenv::app::{Charset, Format};
use shieldenv::domain::{Environment, Pattern, SecretKey};

#[derive(Debug, Parser)]
#[command(
    name = "shieldenv",
    version,
    about = "Encrypted environment vaults with runtime injection",
    propagate_version = true,
    arg_required_else_help = true
)]
pub struct Cli {
    #[arg(
        short,
        long,
        global = true,
        env = "SHIELDENV_ENV",
        default_value = Environment::DEFAULT,
        help = "Environment to use"
    )]
    pub env: Environment,

    #[arg(
        short,
        long,
        global = true,
        help = "Use the user vault instead of the project vault"
    )]
    pub global: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "Create a .shieldenv directory in the current directory")]
    Init,

    #[command(about = "Store a secret; without VALUE it is read from a prompt or stdin")]
    Set {
        key: SecretKey,
        value: Option<String>,
    },

    #[command(about = "Generate a random secret directly into the vault without printing it")]
    Gen {
        key: SecretKey,
        #[arg(
            short,
            long,
            default_value_t = 32,
            value_parser = clap::value_parser!(u16).range(8..=1024)
        )]
        length: u16,
        #[arg(short, long, value_enum, default_value_t = GenCharset::Alphanumeric)]
        charset: GenCharset,
        #[arg(long, help = "Replace the key if it already exists")]
        force: bool,
    },

    #[command(about = "Rename a secret without exposing its value")]
    Mv {
        old: SecretKey,
        new: SecretKey,
        #[arg(long, help = "Replace the new key if it already exists")]
        force: bool,
    },

    #[command(about = "Print a secret value")]
    Get { key: SecretKey },

    #[command(about = "Remove secrets")]
    Rm {
        #[arg(required = true)]
        keys: Vec<SecretKey>,
    },

    #[command(about = "List keys")]
    Ls,

    #[command(about = "Merge secrets from a .env file")]
    Import { file: PathBuf },

    #[command(about = "Export secrets to stdout or a protected file")]
    Export {
        #[arg(short, long, value_enum, default_value_t = ExportFormat::Env)]
        format: ExportFormat,
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
        #[arg(long, requires = "output", help = "Overwrite an existing file")]
        force: bool,
    },

    #[command(about = "Run a command with secrets injected into its environment")]
    Run {
        #[arg(
            long = "only",
            value_name = "GLOB",
            help = "Inject only keys matching the pattern"
        )]
        only: Vec<Pattern>,
        #[arg(
            required = true,
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "COMMAND"
        )]
        command: Vec<OsString>,
    },

    #[command(about = "Compare key names between two environments")]
    Diff {
        left: Environment,
        right: Environment,
    },

    #[command(about = "Copy secrets between environments")]
    Cp {
        #[arg(long, value_name = "ENV")]
        from: Environment,
        #[arg(long, value_name = "ENV")]
        to: Environment,
        #[arg(long, help = "Overwrite keys that already exist in the target")]
        force: bool,
    },

    #[command(about = "Change the master password")]
    Passwd,

    #[command(about = "Show vault information")]
    Status,

    #[command(about = "Check vault integrity")]
    Verify,

    #[command(about = "List environments")]
    Env,

    #[command(about = "Create or use recovery shares")]
    Shares {
        #[command(subcommand)]
        action: SharesCommand,
    },

    #[command(about = "Show the audit log")]
    Log {
        #[arg(short = 'n', long, default_value_t = 20)]
        count: usize,
    },

    #[command(about = "Look for .env files and credentials that should not be committed")]
    Scan {
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    #[command(about = "Print a shell completion script")]
    Completions { shell: Shell },
}

#[derive(Debug, Subcommand)]
pub enum SharesCommand {
    #[command(about = "Split the vault key into recovery shares")]
    Split {
        #[arg(short = 'n', long, value_name = "N", help = "Number of shares")]
        shares: u8,
        #[arg(
            short = 'k',
            long,
            value_name = "K",
            help = "Shares required to recover"
        )]
        threshold: u8,
        #[arg(short, long, value_name = "DIR")]
        output: PathBuf,
    },

    #[command(about = "Recover access from shares and set a new password")]
    Recover {
        #[arg(required = true, num_args = 2.., value_name = "FILE")]
        files: Vec<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum GenCharset {
    Alphanumeric,
    Hex,
    Base64url,
}

impl From<GenCharset> for Charset {
    fn from(charset: GenCharset) -> Self {
        match charset {
            GenCharset::Alphanumeric => Self::Alphanumeric,
            GenCharset::Hex => Self::Hex,
            GenCharset::Base64url => Self::Base64Url,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExportFormat {
    Env,
    Json,
}

impl From<ExportFormat> for Format {
    fn from(format: ExportFormat) -> Self {
        match format {
            ExportFormat::Env => Self::Env,
            ExportFormat::Json => Self::Json,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn run_accepts_flags_after_the_separator() {
        let cli = Cli::try_parse_from([
            "shieldenv",
            "run",
            "--only",
            "DB_*",
            "--",
            "node",
            "--inspect",
            "app.js",
        ])
        .unwrap();
        let Command::Run { only, command } = cli.command else {
            panic!("expected run");
        };
        assert_eq!(only.len(), 1);
        assert_eq!(command, ["node", "--inspect", "app.js"]);
    }

    #[test]
    fn invalid_environment_is_a_usage_error() {
        let error = Cli::try_parse_from(["shieldenv", "-e", "../x", "ls"]).unwrap_err();
        assert_eq!(error.exit_code(), 2);
    }
}
