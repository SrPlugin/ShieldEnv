# ShieldEnv

Encrypted environment vaults for your projects and your team. ShieldEnv stores secrets in
authenticated, encrypted files and injects them into a process only when it runs.

```sh
shieldenv init
shieldenv set DATABASE_URL
shieldenv -e production run -- ./server
```

## Objective

Replace plain-text `.env` files with a tool that keeps secrets encrypted at rest, out of shell
history and the process list, and away from processes that do not need them, while staying as
fast and predictable to use as `git`. Teams get per-person access, revocation and an audit trail
without a server.

## Who It Is For

- **Developers** who juggle API keys, database URLs and tokens across several projects and want
  them out of plain-text files without adopting a hosted secrets service.
- **Freelancers and consultants** who work for several clients: each client grants access to the
  environments it chooses with the freelancer's own identity, and revokes it when the contract ends.
- **Software teams** that need separate `dev`, `staging` and `production` secrets in the repository,
  encrypted, where every person has their own key and the CI system has one of its own.
- **CI pipelines and scripts** that need secrets injected into one command, non-interactively.
- **Security-conscious users** who want an offline, auditable tool with no server, no account and no
  network access.

It is not a replacement for a managed secrets platform such as Vault or AWS Secrets Manager when you
need centralized policy, dynamic credentials or an organization-wide audit trail.

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
code, secrets wiped from memory after use, a versioned vault format and a full test suite. It adds
what teams need on top: identities, members, roles and revocation.

## What It Includes

- **Encrypted vaults** per project and per environment (`dev`, `staging`, `production`, ...).
- **Runtime injection** with `run`, optionally limited to the keys a process needs (`--only 'DB_*'`)
  and able to hand certificates and credential files over as files (`--file`).
- **Git-style workflow**: `init`, `set`, `get`, `rm`, `ls`, `diff`, `cp`, `status`, `log`.
- **Team access**: personal identities, administrators and members, revocation with key rotation,
  and an audit log that names who did what.
- **Git integration**: a merge driver that merges vault files key by key.
- **Secret hygiene**: `gen` creates random secrets without ever printing them, `scan` finds
  plain-text secrets before they are committed, `ls --stale` shows what has not been rotated.
- **History**: the last ten saved states of every vault, with `history` and `restore`.
- **Import and export** of `.env`, JSON, Docker env files and Kubernetes `Secret` manifests.
- **Password rotation and key rotation** (`passwd`, `rekey`).
- **Shamir recovery shares**: split access into `N` shares, recover with any `K` of them.
- **System keyring** support for identities (Secret Service, Keychain, Credential Manager).
- **Shell completions** for bash, zsh, fish, elvish and PowerShell.

## Installation

Requires Rust 1.92 or newer.

```sh
git clone https://github.com/SrPlugin/ShieldEnv.git
cd ShieldEnv
cargo install --path .
```

The system keyring integration is a default Cargo feature. Build a smaller binary without it:

```sh
cargo install --path . --no-default-features
```

## Usage

```sh
shieldenv [-e <ENV>] [-g] <COMMAND>
```

| Option | Description |
|--------|-------------|
| `-e, --env <ENV>` | Environment to use. Defaults to `$SHIELDENV_ENV` or `dev` |
| `-g, --global` | Use the user vault instead of the project vault |

### Secrets

| Command | Description |
|---------|-------------|
| `init` | Create a `.shieldenv/` directory in the current project |
| `set <KEY> [VALUE]` | Store a secret. Without `VALUE` it is read from a hidden prompt or stdin |
| `gen <KEY> [-l N] [-c alphanumeric\|hex\|base64url] [--force]` | Generate a random secret directly into the vault, without printing it |
| `get <KEY>` | Print a secret value |
| `mv <OLD> <NEW> [--force]` | Rename a secret without exposing its value |
| `rm <KEY>...` | Remove secrets |
| `ls [-l] [--stale DAYS]` | List keys, optionally with their last change and only those older than `DAYS` |
| `import <FILE>` | Merge a `.env` file |
| `export [-f env\|json\|docker\|k8s] [-o FILE] [--force]` | Export to stdout or a protected file. `k8s` also takes `--name` and `--namespace` |
| `run [--only <GLOB>]... [--file VAR=KEY]... [--allow-process-hooks] -- <CMD> [ARGS]...` | Run a command with secrets injected |
| `scan [PATH]` | Find `.env` files and credentials that should not be committed |

### Vault management

| Command | Description |
|---------|-------------|
| `diff <ENV_A> <ENV_B>` | Compare key names between environments |
| `cp --from <ENV> --to <ENV> [--force]` | Copy secrets between environments |
| `passwd` | Change the master password |
| `rekey` | Replace the data key and re-encrypt every secret |
| `history` / `restore [N]` | List and return to earlier saved states |
| `status` | Show vault information |
| `verify` | Check vault integrity |
| `env` | List environments |
| `log [-n <N>]` | Show the audit log |
| `shares split -n <N> -k <K> -o <DIR>` / `shares recover <FILE>...` | Create recovery shares and recover access |

### Teams

| Command | Description |
|---------|-------------|
| `id new [--file FILE] [--no-passphrase] [--keyring]` | Create your identity and print its public part |
| `id show` | Print the public part of your identity |
| `member init <NAME>` | Make your identity the first administrator of a vault |
| `member add <NAME> <PUBLIC> [--admin]` | Give a person or a CI system access |
| `member rm <NAME>` | Revoke access and rotate the data key |
| `member ls` | List the members of a vault |
| `trust accept` | Approve the current administrators of a vault after reviewing them |
| `git-setup` | Make git merge vault files key by key |
| `completions <SHELL>` | Print a shell completion script |

### Examples

```sh
shieldenv init
shieldenv set API_KEY
printf '%s' "$TOKEN" | shieldenv set GITHUB_TOKEN
shieldenv gen JWT_SECRET --length 64
shieldenv import .env

shieldenv -e production set DATABASE_URL
shieldenv diff staging production
shieldenv -e production run --only 'DB_*' -- ./migrate
shieldenv -e production run --file GOOGLE_APPLICATION_CREDENTIALS=GCP_KEY -- ./app

shieldenv export -f k8s --namespace payments | kubectl apply -f -
shieldenv ls --stale 90
shieldenv scan

shieldenv shares split -n 3 -k 2 -o ~/recovery
shieldenv shares recover share-1.txt share-3.txt
```

### Passwords and environment variables

The master password is read from `SHIELDENV_PASSWORD` when set, otherwise from a hidden
terminal prompt with three attempts. There is no password flag. New passwords need at least
12 characters and are confirmed when typed.

| Variable | Purpose |
|----------|---------|
| `SHIELDENV_PASSWORD` | Master password for non-interactive use |
| `SHIELDENV_NEW_PASSWORD` | New password for `passwd` and `shares recover` without a prompt |
| `SHIELDENV_ENV` | Default environment instead of `dev` |
| `SHIELDENV_IDENTITY` | The secret text of an identity, for CI systems |
| `SHIELDENV_IDENTITY_FILE` | Path of an identity file |
| `SHIELDENV_IDENTITY_PASSPHRASE` | Passphrase of an identity file, for non-interactive use |
| `SHIELDENV_NO_KEYRING` | Set to skip the system keyring |

Every credential variable is removed from the environment of the processes started with `run`.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Error, `diff` found differences or `scan` found secrets |
| `2` | Invalid usage, including invalid keys and environment names |
| `126`, `127` | `run` could not start the command |
| other | `run` returns the exit code of the command |

## Working With a Team

By default a vault opens with its password. Identities replace the shared password: every person
and every CI system gets its own key, and an administrator decides who may open which environment.

```sh
# everyone, once
shieldenv id new                                  # prints shieldenv-public1:...

# the first administrator, once per environment
shieldenv -e production member init alice
shieldenv -e production member add bob 'shieldenv-public1:...'
shieldenv -e production member add ci  'shieldenv-public1:...'

# bob, with no password
shieldenv -e production get DATABASE_URL

# the pipeline: SHIELDENV_IDENTITY holds the CI identity as a secret
shieldenv -e production run -- ./deploy

# offboarding: removes access and rotates the data key
shieldenv -e production member rm bob
```

- **Roles.** Administrators manage members; members read and write secrets. The member list is
  signed by an administrator, so nobody else can add a member without every other person noticing.
- **Offboarding.** `member rm` rotates the data key, so the former member cannot open new versions.
  They have already seen the values they could read, so change those secrets too. Password access
  is removed at the same time because the former member may know it; set a new one with `passwd`.
- **Least privilege.** Give people only the environments they need. Production can stay with
  administrators and the CI identity.
- **Audit.** `shieldenv log` shows the member name behind every operation.

### Trust

The first time you open a vault that has members, ShieldEnv remembers who its administrators are, on
your machine only, much like SSH remembers host keys. From then on:

- a member list signed by someone you never trusted is refused, so a member cannot promote
  themselves to administrator or lock the real administrators out;
- a vault whose generation goes backwards is refused as a likely rollback;
- a legitimate change you have not seen yet, for example an administrator you never met who took over
  while you were away, is refused until you review it with `member ls` and run `trust accept`.

Someone cloning a repository for the first time has nothing to compare against, so check the
fingerprints that ShieldEnv prints at first use with the people who run the project.

Where your identity lives, in lookup order:

1. `SHIELDENV_IDENTITY` (CI systems).
2. The file named by `SHIELDENV_IDENTITY_FILE`.
3. `~/.config/shieldenv/identity`, encrypted with a passphrase (the default of `id new`).
4. The system keyring (`id new --keyring`).

### Git

Two people changing the same vault on different branches would normally leave git with an
unmergeable binary file. Run this once in every clone and commit `.gitattributes`:

```sh
shieldenv git-setup
```

Git then merges `.shieldenv/*.vault` key by key. Changes to different keys combine; a key changed
differently on both sides stops the merge and is reported by name, never by value.

## How It Works

### Vault resolution

ShieldEnv walks up from the current directory to the nearest `.shieldenv/`, the same way `git`
finds `.git`. Each environment is one file inside it:

```
my-project/
└── .shieldenv/
    ├── dev.vault
    ├── production.vault
    ├── audit.log          ignored by git
    ├── history/           ignored by git
    └── .gitignore
```

With `--global`, vaults live in the user data directory (`~/.local/share/shieldenv` on Linux).
Environment names are restricted to `[a-z0-9][a-z0-9_-]{0,63}`, so they can never escape the
vault directory. Like `git`, ShieldEnv refuses a `.shieldenv/` directory owned by another user,
so a directory planted in a shared location such as `/tmp` is never used.

### Encryption

```
password ──Argon2id──▶ key ──wraps──▶ ┐
member identity (X25519) ──wraps──▶   ├─ data key ──encrypts──▶ secrets
more members ...                      ┘
```

1. A random 256-bit data key encrypts the secrets with XChaCha20-Poly1305.
2. The data key is wrapped once per way of opening the vault: by a key derived from the password with
   Argon2id (64 MiB, 3 passes, 4 lanes), and by each member's X25519 key using the `age` format.
3. The whole header, including the version, the KDF parameters and every access slot, is
   authenticated. Changing a single byte of the file makes decryption fail.

Changing the password or the members re-wraps 32 bytes instead of re-encrypting the vault, and
recovery shares split the data key, so they keep working after a password change.

### Vault format

```
"SHLD" | version 2 | vault id | generation | access slots | member signature | payload nonce | ciphertext
```

The format is versioned and the Argon2 parameters are bounded when read, so a crafted file cannot
exhaust memory or force weak settings. The payload is a length-prefixed binary encoding with hard
size limits and a creation and update time for every secret. The list of members carries an
Ed25519 signature by an administrator, bound to the vault id so it cannot be moved to another vault.

### Writing safely

Every change follows the same path: exclusive lock, decrypt, modify in memory, keep the previous
state in `history/`, encrypt with a fresh nonce, write to a random temporary file with `0600`
permissions, `fsync`, atomic rename, `fsync` the directory, release the lock. A crash leaves either
the old vault or the new one, never a partial file. Readers take a shared lock and never see a
half-written vault.

### Running commands

`run` decrypts the vault, filters keys if `--only` is given, removes every credential variable and
replaces itself with the target command on Unix (`exec`), so signals and exit codes behave exactly
as if the command had been started directly. The command inherits the disabled core dumps, since
its environment now holds the secrets.

`--file VAR=KEY` hands a secret over as a file whose path is stored in `VAR`, which suits TLS
certificates and cloud credential files. On Linux the file lives in memory (`memfd`) and never
touches the disk; the command and its children can read every file delivered this way. Elsewhere
it is a `0600` temporary file removed when the command exits, which an abrupt kill can leave behind.

Variables that change how programs load code, such as `PATH`, `LD_PRELOAD` or `NODE_OPTIONS`, are
not injected unless you pass `--allow-process-hooks`, so a vault someone else prepared cannot
quietly redirect a trusted program.

## Architecture

The crate is a library with a thin binary on top. Dependencies point inward only:

```
cli ──▶ app ──▶ storage ──▶ crypto ──▶ domain
```

| Layer | Responsibility |
|-------|----------------|
| `domain` | Validated types: secret keys, environment names, member names, the secrets map, glob patterns. No I/O |
| `crypto` | Argon2id, envelope encryption, identities, vault header, Shamir secret sharing. No I/O |
| `storage` | Workspace discovery, binary codec, atomic writes, file locks, history, audit log, identity files, keyring |
| `app` | Use cases: open, modify and merge vaults under lock; formats; generators; the secret scanner |
| `cli` | Binary only: argument parsing, prompts, authentication, process hardening, output and exit codes |

```
src/
├── lib.rs
├── error.rs              single error type
├── wire.rs               panic-free binary reader
├── domain/               key, environment, member, secrets, pattern
├── crypto/               kdf, envelope, identity, identity_file, shamir, hex
├── storage/              workspace, codec, file, history, audit, keystore, keyring, secretfile
├── app/                  vault, format, generate, scan, merge
├── main.rs
└── cli/                  args, commands, members, identity, git, auth, context, prompt, output, hardening
tests/
└── cli.rs                end-to-end tests, including real git merges
```

## Security

| Threat | Protection |
|--------|------------|
| Vault file leaked or committed | Argon2id + XChaCha20-Poly1305, authenticated header |
| Tampered or crafted vault | Every byte authenticated, bounded parameters, size limits, panic-free parsing |
| Someone adds themselves to a vault | The member list is signed by an administrator, and the administrators you trusted are remembered locally |
| Vault replaced by an older version | The highest generation seen is remembered; going back is refused |
| A hostile branch rewrites access when merging | Merges require the same vault in all three files and re-check trust |
| A vault injects `LD_PRELOAD` or `PATH` | `run` withholds loader and interpreter variables by default |
| A `.env` export is sourced in a shell | Values are quoted so `$(...)` and backticks stay literal |
| Symbolic links planted in `.shieldenv/` | Never followed for logs, locks or history |
| A removed member keeps reading | Data key rotation, history cleared, password access removed |
| Secrets in `ps` or shell history | No password flag, values from a hidden prompt or stdin, `gen` never prints |
| Credentials leaking to child processes | Password and identity variables removed before `run` |
| Path traversal | Validated environment names |
| Planted vault directories | Directories owned by other users are refused |
| Crash during write | Atomic writes with `fsync` |
| Concurrent invocations | File locks |
| Secrets left in memory | Zeroized on drop |
| Core dumps and debugger attach | `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0` on Linux |
| Brute force on a stolen vault | Argon2id with 64 MiB of memory per guess |
| Identity file stolen | Encrypted with a passphrase; plain files must be `0600` |
| Secrets committed by mistake | `scan` finds `.env` files and well-known credential formats |

The crate forbids `unsafe` code and release builds abort on panic.

Not covered:

- Malware running as your user while a vault is open, and a compromised operating system.
- A rollback on a machine that has never opened the vault before: with nothing remembered there is
  nothing to compare, so use git history to review changes to vault files.
- A member who is also a bad actor can still read everything in the environments they belong to.
- Secrets a former member already read. Rotate them.

## Development

```sh
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Tests run at three levels: unit tests inside each module, property-based tests with `proptest`
for parsers and Shamir sharing, and end-to-end tests that drive the compiled binary in an
isolated home directory, including real `git` merges.

ShieldEnv is developed and tested on Linux. The macOS and Windows code paths exist but have not
been exercised yet.

## License

MIT. See [LICENSE](LICENSE).

## Author

Sebastian Cheikh
