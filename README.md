# temp-ssh-key

[![ci](https://github.com/kwtucker/temp-ssh-key/actions/workflows/ci.yml/badge.svg)](https://github.com/kwtucker/temp-ssh-key/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/kwtucker/temp-ssh-key)](https://github.com/kwtucker/temp-ssh-key/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/kwtucker/temp-ssh-key.svg)](https://pkg.go.dev/github.com/kwtucker/temp-ssh-key)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Create a disposable Ed25519 SSH key on an untrusted machine, authorize only its
public key on a trusted device, use it for one git operation, then revoke and
delete it.

`temp-ssh-key` handles the local mechanics: a private temporary directory, key
generation, public-key display as text, a terminal QR code, or a PNG, an
isolated shell, eval-safe Git exports, and a guarded cleanup.

It never contacts a remote, edits your SSH or Git configuration, adds a key to
`ssh-agent`, or revokes authorization. Authorizing and revoking the key is
always a separate, manual step on a trusted device. **Deleting local files is
not revocation.**

## Install

With mise:

```sh
mise use -g github:kwtucker/temp-ssh-key@0.2.1
```

With Go:

```sh
go install github.com/kwtucker/temp-ssh-key/cmd/temp-ssh-key@latest
```

Or download a release archive for Linux or macOS (amd64/arm64), verify
`checksums.txt`, and put the binary on `PATH`.

`ssh-keygen` must be available. Git 2.32 or newer is required for the
`GIT_CONFIG_GLOBAL` and `GIT_CONFIG_SYSTEM` isolation variables; earlier
versions still work if you pass `--no-isolate-config`.

## Verify a release

Release archives are built from a tagged commit by the GitHub Actions release
workflow. Verify the checksum before running a downloaded binary:

```sh
# Linux example; adjust the file name for your OS and architecture.
curl -LO https://github.com/kwtucker/temp-ssh-key/releases/download/v0.2.1/temp-ssh-key_0.2.1_linux_amd64.tar.gz
curl -LO https://github.com/kwtucker/temp-ssh-key/releases/download/v0.2.1/checksums.txt
grep "temp-ssh-key_0.2.1_linux_amd64.tar.gz$" checksums.txt | sha256sum -c -
```

On macOS, use `shasum -a 256 -c -` instead of `sha256sum -c -`.

The release workflow also attests the archives and `checksums.txt` with GitHub
artifact attestations. Auditors with an authenticated GitHub CLI can check the
build provenance:

```sh
gh attestation verify temp-ssh-key_0.2.1_linux_amd64.tar.gz \
  --repo kwtucker/temp-ssh-key
```

Checksums remain the primary manual check; attestations are optional and
depend on GitHub's hosted service.

## Quick start

Convenience flow — create the key and enter a ready-to-use isolated shell in
one command:

```sh
temp-ssh-key start --format qr \
  --name "Your Name" --email "you@example.com"
```

`start` exports the key paths, `GIT_SSH_COMMAND`, `GIT_TERMINAL_PROMPT=0`, the
Git config override, the identity, and Git config isolation into the new shell.
Scan the QR code on the trusted device and authorize the public key there. Then
do the Git work:

```sh
git add -A
git commit -m "message"
git push git@github.com:OWNER/REPO.git HEAD:main
```

After revoking the key on the trusted device:

```sh
temp-ssh-key cleanup --remove
exit
```

Strict flow — generate the key *inside* the isolated shell, so even the
generation command is absent from the parent shell's history:

```sh
temp-ssh-key shell
eval "$(temp-ssh-key create --format qr)"
eval "$(temp-ssh-key env "$KEY_DIR" --name "Your Name" --email "you@example.com")"
# ... git work ...
temp-ssh-key cleanup --remove
exit
```

## Commands

| Command | Purpose |
|---|---|
| `create` | Generate a key and print only the public artifact. |
| `shell [KEY_DIR]` | Enter a history-isolated `zsh` or `bash`. |
| `start` | Create a key, export the session environment, and enter an isolated shell. |
| `show KEY_DIR` | Verify a key directory and display its public key. |
| `env KEY_DIR` | Print eval-safe Git and key exports. |
| `cleanup [KEY_DIR]` | Print or remove this tool's local files (defaults to `$KEY_DIR`). |
| `--version` | Print the version. |

Run `temp-ssh-key <command> --help` for flags.

### `create`

```sh
eval "$(temp-ssh-key create --format qr)"
```

stdout contains exactly two eval-safe assignments:

```sh
KEY_DIR='/tmp/temp-ssh-key.abc123'
KEY_FINGERPRINT='SHA256:...'
```

The public key, QR code, PNG path, and warnings go to stderr. That split is what
makes `eval` safe while the QR code still renders. Because stdout is captured,
`create` only needs a terminal on stdin (for the passphrase) and on stderr (for
QR output); captured stdout is fine.

Creation prompts for a passphrase through `ssh-keygen`. The passphrase is never
passed as an argument, environment variable, or file. `--allow-unencrypted`
skips the passphrase and is never implicit.

`--format png` writes `public-key.png` inside the key directory and prints its
path. Repeating the command overwrites the file atomically, so a crashed or
interrupted write cannot leave a partial image behind. QR output requires a
terminal on stderr.

### `show`

```sh
temp-ssh-key show "$KEY_DIR"              # text
temp-ssh-key show "$KEY_DIR" --format qr  # terminal QR code
temp-ssh-key show "$KEY_DIR" --format png # write public-key.png
```

`show` verifies that the private key is readable and that its public half
matches `id_ed25519.pub` before displaying anything. It rejects mismatched,
missing, or malformed files. A passphrase is not needed for this check because
the public half of an OpenSSH private key is stored unencrypted. PNG output is
repeatable and replaces an existing image atomically.

### `shell` and `start`

`shell` starts a new `zsh -f` or `bash --noprofile --norc` with history storage
disabled (`HISTFILE=/dev/null` and `SAVEHIST=0` or `HISTSIZE=0`). The marker
`TEMP_SSH_KEY_ISOLATED=1` prevents nesting. If you already started an isolated
shell manually with the same history settings, `shell` recognizes it too.

`start` is the convenience composition. It creates the key, exports the same
environment as `env`, and replaces the process, so the parent shell records only
`start`. Pass `--name` and `--email` to export the commit identity; without them
the isolated shell has no identity unless the repository sets one. Use
`--no-isolate-config` to keep your normal Git config. Inside an isolated shell
`start` refuses to nest and points you at `create`.

Both `start` and `shell` print a short next-steps banner, including the
revoke-before-cleanup reminder.

### `env`

```sh
eval "$(temp-ssh-key env "$KEY_DIR" --name "Your Name" --email "you@example.com")"
```

This exports `KEY_DIR`, `KEY`, `KEY_FINGERPRINT`, `GIT_SSH_COMMAND`,
`GIT_TERMINAL_PROMPT=0`, a `core.sshCommand` override, and optionally the author
and committer identity. By default it also sets `GIT_CONFIG_GLOBAL=/dev/null`
and `GIT_CONFIG_SYSTEM=/dev/null` so global rewrite rules, signing
configuration, and identity do not leak into the operation. Use
`--no-isolate-config` to keep your normal Git config.

`shell KEY_DIR` exports the same session environment directly into the new
shell, so `env` is only needed in the strict flow.

### `cleanup`

```sh
temp-ssh-key cleanup            # print the rm/rmdir commands for $KEY_DIR
temp-ssh-key cleanup --remove   # prompt per file, then rmdir
temp-ssh-key cleanup /path/to/key --remove
```

`KEY_DIR` defaults to `$KEY_DIR`, which `start`, `shell KEY_DIR`, and `env`
export. Passing the path explicitly still works.

Cleanup refuses directories that are symlinks, not owned by you, not mode 700,
or not named `temp-ssh-key.*`. It also refuses to touch a directory containing
anything other than `id_ed25519`, `id_ed25519.pub`, and `public-key.png`.

`--remove` requires an interactive terminal on both stdin and stderr. Prompts
are written to stderr so they do not mix with command output, and stdout may be
captured. A failed prompt write aborts before deleting anything.

## Security model

This tool is for reducing exposure on a machine you do not control. It is not an
anonymity tool, and it does not protect against a compromised operating system,
a keylogger, or a malicious `ssh-keygen` on `PATH`.

- Never sign in to your personal account on the untrusted machine.
- Authorize and revoke the key from a trusted device.
- Use a passphrase unless you have a specific reason not to.
- Transfer only the public key. Never copy the private key.
- Revoke remote authorization before deleting local files.
- Treat the isolated shell as a convenience, not as a security boundary.

## Non-goals

- Revoking remote authorization, editing SSH or Git configuration, or managing
  `ssh-agent`. Those remain manual steps on a trusted device.
- Replacing a general SSH or secret manager, or managing long-lived keys.
- Protecting against a compromised operating system, keylogger, or malicious
  binaries on `PATH`.
- Providing anonymity or attribution resistance.
- Supporting Windows releases.

## Development

The development targets expect `golangci-lint` v2 and `govulncheck` on `PATH`.

```sh
make fmt        # gofumpt + goimports via golangci-lint
make fmt-check
make lint       # golangci-lint run
make vuln       # govulncheck ./...
make test
make check      # formatting, lint, tests, and vulnerabilities
make build
```

Linting uses `.golangci.yml` with `default: none` and an explicit set of
linters. Tests are local and offline. They fake `ssh-keygen` where needed and
never contact a remote.

CI runs lint, a module-tidiness check, `govulncheck`, and tests; tests run on
Linux and macOS while lint and vulnerability checks run on Linux. Tagging `v*`
runs the same CI workflow before GoReleaser builds Linux and macOS release
archives for amd64 and arm64 with `CGO_ENABLED=0` and attests the published
artifacts.

Release notes are generated from commit messages. Test and chore commits are
excluded; documentation commits are included.

## License

MIT. See [LICENSE](LICENSE).
