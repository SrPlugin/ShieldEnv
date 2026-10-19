# ShieldEnv

Encrypted environment vaults for your projects. ShieldEnv stores secrets in authenticated,
password-protected files and injects them into a process only when it runs.

```sh
shieldenv init
shieldenv set DATABASE_URL
shieldenv -e production run -- ./server
```

## Objective

Replace plain-text `.env` files with a tool that keeps secrets encrypted at rest, out of shell
history and the process list, and away from processes that do not need them, while staying as
fast and predictable to use as `git`.

## Who It Is For

- **Developers** who juggle API keys, database URLs and tokens across several projects and want
  them out of plain-text files without adopting a hosted secrets service.
- **Small teams** that need separate `dev`, `staging` and `production` secrets in the repository,
  encrypted, with recovery shares instead of a single person holding the only password.
- **Freelancers and consultants** working on client projects where a leaked `.env` is not an option.
- **CI pipelines and scripts** that need secrets injected into one command, non-interactively, through
  `SHIELDENV_PASSWORD`.
- **Security-conscious users** who want an offline, auditable tool with no server, no account and no
  network access.

It is not a replacement for a managed secrets platform such as Vault or AWS Secrets Manager when you
need centralized access control, dynamic credentials or audit trails across an organization.

## Why ShieldEnv Exists

`.env` files are convenient and dangerous: they get committed, copied into backups, read by any
process running as your user and dumped into crash reports.

ShieldEnv is the successor of GhostEnv, a Go tool built to solve that problem. A security review
of GhostEnv found weaknesses that could not be fixed incrementally:

- environment names were used as file paths without validation, allowing path traversal;
- the master password leaked into every child process started with `run`;
- a cloned repository could weaken the key derivation through its configuration file;
- the vault integrity check ignored failures;
- passwords and values were passed as command-line arguments, visible in `ps` and shell history;
- writes were neither atomic nor locked;
- recovery shares became useless after a password change.

ShieldEnv is a rewrite in Rust that closes every one of these gaps by design, with memory-safe
code, secrets wiped from memory after use, a versioned vault format and a full test suite.

## What It Includes

- **Encrypted vaults** per project and per environment (`dev`, `staging`, `production`, ...).
- **Runtime injection** with `run`, optionally limited to the keys a process needs (`--only 'DB_*'`).
- **Git-style workflow**: `init`, `set`, `get`, `rm`, `ls`, `diff`, `cp`, `status`, `log`.
- **Import** from `.env` files and **export** to `.env` or JSON, with quoting that survives any value.
- **Password rotation** without re-encrypting secrets.
- **Shamir recovery shares**: split access into `N` shares, recover with any `K` of them.
- **Audit log** of every operation, recording key names but never values.
- **Shell completions** for bash, zsh, fish, elvish and PowerShell.

## Installation

Requires Rust 1.92 or newer.

```sh
git clone https://github.com/SrPlugin/ShieldEnv.git
cd ShieldEnv
cargo install --path .
```

## Usage

```sh
shieldenv [-e <ENV>] [-g] <COMMAND>
```

| Option | Description |
|--------|-------------|
| `-e, --env <ENV>` | Environment to use. Defaults to `$SHIELDENV_ENV` or `dev` |
| `-g, --global` | Use the user vault instead of the project vault |

| Command | Description |
|---------|-------------|
| `init` | Create a `.shieldenv/` directory in the current project |
| `set <KEY> [VALUE]` | Store a secret. Without `VALUE` it is read from a hidden prompt or stdin |
| `get <KEY>` | Print a secret value |
| `rm <KEY>...` | Remove secrets |
| `ls` | List keys |
| `import <FILE>` | Merge a `.env` file |
| `export [-f env\|json] [-o FILE] [--force]` | Export secrets to stdout or a protected file |
| `run [--only <GLOB>]... -- <CMD> [ARGS]...` | Run a command with secrets injected |
| `diff <ENV_A> <ENV_B>` | Compare key names between environments |
| `cp --from <ENV> --to <ENV> [--force]` | Copy secrets between environments |
| `passwd` | Change the master password |
| `status` | Show vault information |
| `verify` | Check vault integrity |
| `env` | List environments |
| `shares split -n <N> -k <K> -o <DIR>` | Create recovery shares |
| `shares recover <FILE>...` | Recover access and set a new password |
| `log [-n <N>]` | Show the audit log |
| `completions <SHELL>` | Print a shell completion script |

### Examples

```sh
shieldenv init
shieldenv set API_KEY
printf '%s' "$TOKEN" | shieldenv set GITHUB_TOKEN
shieldenv import .env

shieldenv -e production set DATABASE_URL
shieldenv diff staging production
shieldenv -e production run --only 'DB_*' -- ./migrate

shieldenv shares split -n 3 -k 2 -o ~/recovery
shieldenv shares recover share-1.txt share-3.txt
```

### Passwords

The master password is read from `SHIELDENV_PASSWORD` when set, otherwise from a hidden
terminal prompt with three attempts. There is no password flag. New passwords need at least
12 characters and are confirmed when typed.

| Variable | Purpose |
|----------|---------|
| `SHIELDENV_PASSWORD` | Master password for non-interactive use (CI, scripts) |
| `SHIELDENV_NEW_PASSWORD` | New password for `passwd` and `shares recover` without a prompt |
| `SHIELDENV_ENV` | Default environment instead of `dev` |

Both password variables are removed from the environment of every process started with `run`.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Error, or differences found by `diff` |
| `2` | Invalid usage, including invalid keys and environment names |
| `126`, `127` | `run` could not start the command |
| other | `run` returns the exit code of the command |

## How It Works

### Vault resolution

ShieldEnv walks up from the current directory to the nearest `.shieldenv/`, the same way `git`
finds `.git`. Each environment is one file inside it:

```
my-project/
└── .shieldenv/
    ├── dev.vault
    ├── staging.vault
    ├── production.vault
    ├── audit.log
    └── .gitignore
```

With `--global`, vaults live in the user data directory (`~/.local/share/shieldenv` on Linux).
Environment names are restricted to `[a-z0-9][a-z0-9_-]{0,63}`, so they can never escape the
vault directory. Like `git`, ShieldEnv refuses a `.shieldenv/` directory owned by another user,
so a directory planted in a shared location such as `/tmp` is never used.

### Encryption

```
password ──Argon2id──▶ KEK ──wraps──▶ DEK ──encrypts──▶ secrets
```

1. A random 256-bit data key (DEK) encrypts the secrets with XChaCha20-Poly1305.
2. The master password is stretched with Argon2id (64 MiB, 3 passes, 4 lanes) into a key
   encryption key (KEK) that wraps the DEK.
3. The whole header, including the version and Argon2 parameters, is authenticated. Changing a
   single byte of the file makes decryption fail.

Changing the password re-wraps 32 bytes instead of re-encrypting the vault, and recovery shares
split the DEK, so they keep working after a password change.

### Vault format

```
"SHLD" | version | argon2 m,t,p | salt | key-wrap nonce | wrapped DEK | payload nonce | ciphertext
```

The format is versioned, the Argon2 parameters are bounded when read so a crafted file cannot
exhaust memory or force weak settings, and the payload is a length-prefixed binary encoding with
hard size limits.

### Writing safely

Every change follows the same path: exclusive lock, decrypt, modify in memory, encrypt with a
fresh nonce, write to a random temporary file with `0600` permissions, `fsync`, atomic rename,
`fsync` the directory, release the lock. A crash leaves either the old vault or the new one,
never a partial file. Readers take a shared lock and never see a half-written vault.

### Running commands

`run` decrypts the vault, filters keys if `--only` is given, removes the password variables and
replaces itself with the target command on Unix (`exec`), so signals and exit codes behave
exactly as if the command had been started directly. On Windows the exit code is propagated.
The command inherits the disabled core dumps, since its environment now holds the secrets.

## Architecture

The crate is a library with a thin binary on top. Dependencies point inward only:

```
cli ──▶ app ──▶ storage ──▶ crypto ──▶ domain
```

| Layer | Responsibility |
|-------|----------------|
| `domain` | Validated types: secret keys, environment names, the secrets map, glob patterns. No I/O |
| `crypto` | Argon2id, envelope encryption, vault header, Shamir secret sharing. No I/O |
| `storage` | Workspace discovery, binary codec, atomic writes, file locks, audit log |
| `app` | Use cases: open, modify and save vaults under lock; `.env` and JSON formats |
| `cli` | Binary only: argument parsing, prompts, process hardening, output and exit codes |

```
src/
├── lib.rs
├── error.rs              single error type
├── wire.rs               panic-free binary reader
├── domain/
│   ├── key.rs            SecretKey
│   ├── environment.rs    Environment
│   ├── secrets.rs        Secrets
│   └── pattern.rs        Pattern
├── crypto/
│   ├── kdf.rs            Argon2id
│   ├── envelope.rs       vault header and envelope encryption
│   └── shamir.rs         GF(2^8) secret sharing
├── storage/
│   ├── workspace.rs      .shieldenv discovery
│   ├── codec.rs          payload encoding
│   ├── file.rs           atomic writes and locks
│   └── audit.rs          audit log
├── app/
│   ├── vault.rs          Vault service
│   └── format.rs         .env and JSON
├── main.rs
└── cli/
    ├── args.rs           command definitions
    ├── commands.rs       command handlers
    ├── prompt.rs         passwords and values
    └── hardening.rs      process hardening
tests/
└── cli.rs                end-to-end tests
```

## Security

| Threat | Protection |
|--------|------------|
| Vault file leaked or committed | Argon2id + XChaCha20-Poly1305, authenticated header |
| Tampered or crafted vault | Every byte authenticated, bounded parameters, size limits, panic-free parsing |
| Secrets in `ps` or shell history | No password flag, values from a hidden prompt or stdin |
| Password leaking to child processes | Removed from the environment before `run` |
| Path traversal | Validated environment names |
| Planted vault directories | Directories owned by other users are refused |
| Crash during write | Atomic writes with `fsync` |
| Concurrent invocations | File locks |
| Secrets left in memory | Zeroized on drop |
| Core dumps and debugger attach | `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0` on Linux |
| Brute force on a stolen vault | Argon2id with 64 MiB of memory per guess |

The crate forbids `unsafe` code and release builds abort on panic.

Not covered: malware running as your user while a vault is open, and a compromised operating
system.

## Development

```sh
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Tests run at three levels: unit tests inside each module, property-based tests with `proptest`
for parsers and Shamir sharing, and end-to-end tests that drive the compiled binary in an
isolated home directory.

## License

MIT. See [LICENSE](LICENSE).

## Author

Sebastian Cheikh
