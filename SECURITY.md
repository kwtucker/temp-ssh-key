# Security policy

## Supported versions

Security fixes are provided for the latest tagged release. Older releases are
not maintained; upgrade with `mise`, `go install`, or a current release
archive.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability
reporting:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**.
3. Describe the issue, affected version, platform, and reproduction steps.

Do not open a public issue for an unpatched vulnerability. Do not include
private keys, passphrases, tokens, or other secrets in a report.

Reports are handled on a best-effort basis. There is no bug bounty program.
Please allow time for a fix and coordinated disclosure before publishing
details.

## Threat model

`temp-ssh-key` reduces the time a private key exists on a machine you do not
control. It does not make that machine trustworthy.

In scope:

- Accidental disclosure of private key material through stdout, stderr, or
  process arguments.
- Unsafe shell quoting in the `eval`-able exports.
- Cleanup deleting or inspecting paths it does not own, including symlinks,
  unexpected files, and directories outside the managed layout.
- Weak file or directory permissions created or accepted by the tool.
- Mishandling of `ssh-keygen` failures or partial key directories.

Out of scope:

- A compromised operating system, firmware, boot chain, or hypervisor.
- Keyloggers, screen capture, malicious terminals, or malicious `ssh-keygen`
  or `ssh` binaries on `PATH`.
- Compromise of the trusted device, the remote Git host, or the SSH server.
- Git, SSH, or shell vulnerabilities outside this project's code.
- Anonymity, attribution resistance, or protection against network observers.
- Failing to revoke remote authorization. Revocation is always a separate,
  manual step on a trusted device; deleting local files is not revocation.
- A key that is authorized longer than intended because the user skipped the
  revoke step.

## Security model

The README documents the intended operating model and remaining risks. Treat
the isolated shell as a convenience against shell history, not as a security
boundary.
