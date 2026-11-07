# temp-ssh-key

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
mise use -g github:kwtucker/temp-ssh-key@0.1.0
```

With Go:

```sh
go install github.com/kwtucker/temp-ssh-key/cmd/temp-ssh-key@latest
```

Or download a release archive for Linux or macOS (amd64/arm64), verify
`checksums.txt`, and put the binary on `PATH`.

`ssh-keygen` must be available. Nothing else is required at runtime.

## Quick start

Convenience flow — create the key and enter an isolated shell in one command:

```sh
temp-ssh-key start --format qr
```

Scan the QR code on the trusted device and authorize the public key there. In
the isolated shell:

```sh
eval "$(temp-ssh-key env "$KEY_DIR" \
  --name "Your Name" --email "you@example.com")"

ssh -F /dev/null -o IdentitiesOnly=yes -i "$KEY" -T git@github.com
git add -A
git commit -m "message"
git push git@github.com:OWNER/REPO.git HEAD:main

# After revoking the key on the trusted device:
temp-ssh-key cleanup "$KEY_DIR" --remove
exit
```

Strict flow — generate the key *inside* the isolated shell, so even the
generation command is absent from the parent shell's history:

```sh
temp-ssh-key shell
eval "$(temp-ssh-key create --format qr)"
eval "$(temp-ssh-key env "$KEY_DIR" --name "Your Name" --email "you@example.com")"
# ... git work ...
temp-ssh-key cleanup "$KEY_DIR" --remove
exit
```

## Commands

| Command | Purpose |
|---|---|
| `create` | Generate a key and print only the public artifact. |
| `shell [KEY_DIR]` | Enter a history-isolated `zsh` or `bash`. |
| `start` | `create` then `shell`. |
| `show KEY_DIR` | Verify a key directory and display its public key. |
| `env KEY_DIR` | Print eval-safe Git and key exports. |
| `cleanup KEY_DIR` | Print or remove this tool's local files. |
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
path. QR output requires a terminal on stderr.

### `shell` and `start`

`shell` starts a new `zsh -f` or `bash --noprofile --norc` with history storage
disabled (`HISTFILE=/dev/null` and `SAVEHIST=0` or `HISTSIZE=0`). The marker
`TEMP_SSH_KEY_ISOLATED=1` prevents nesting. If you already started an isolated
shell manually with the same history settings, `shell` recognizes it too. When a
key directory is given, it exports `KEY_DIR`, `KEY`, and `KEY_FINGERPRINT`.

`start` is the convenience composition. It replaces the process, so the parent
shell records only `start`. Inside an isolated shell it refuses to nest and
points you at `create`.

### `env`

```sh
eval "$(temp-ssh-key env "$KEY_DIR" --name "Your Name" --email "you@example.com")"
```

This exports `KEY_DIR`, `KEY`, `GIT_SSH_COMMAND`, a `core.sshCommand` override,
and optionally the author and committer identity. By default it also sets
`GIT_CONFIG_GLOBAL=/dev/null` and `GIT_CONFIG_SYSTEM=/dev/null` so global
rewrite rules, signing configuration, and identity do not leak into the
operation. Use `--no-isolate-config` to keep your normal Git config.

### `cleanup`

```sh
temp-ssh-key cleanup "$KEY_DIR"          # print the rm/rmdir commands
temp-ssh-key cleanup "$KEY_DIR" --remove # prompt per file, then rmdir
```

Cleanup refuses directories that are symlinks, not owned by you, not mode 700,
or not named `temp-ssh-key.*`. It also refuses to touch a directory containing
anything other than `id_ed25519`, `id_ed25519.pub`, and `public-key.png`.

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

## Development

```sh
make test
make vet
make build
```

Tests are local and offline. They fake `ssh-keygen` where needed and never
contact a remote.

Releases are built by GoReleaser for Linux and macOS on amd64 and arm64 with
`CGO_ENABLED=0`. Tagging `v*` runs the release workflow.

## License

MIT. See [LICENSE](LICENSE).
