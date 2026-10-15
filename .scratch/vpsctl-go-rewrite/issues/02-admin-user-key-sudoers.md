# Admin User, key install/rotation, sudoers

Status: resolved
Milestone: M1
Blocked by: 01

## What
- Create Admin User (adduser/useradd, key-only, no password), add to admin group, per-user NOPASSWD sudoers validated with `visudo -cf` and installed atomically (sorts after any `%wheel` rule).
- ed25519 keypair generation in a private temp dir; install pubkey (700/600, owner, `restorecon` on SELinux); emit private key to a real TTY or `--key-out` (600). Key-emitted marker under `/var/lib/vpsctl`; installed-but-never-emitted key → refuse unless `--rotate-key`.
- Lock Default Cloud Users (lock, nologin, empty authorized_keys); cloud-init drop-in blocking re-injection.

## Acceptance (tests first)
- sudo is installed BEFORE any sudoers file is written (image without sudo works).
- Existing system user (UID < 1000) or a Default Cloud User name as `--user` → refused.
- Private key temp dir removed on every path, including failures mid-way.
- No controlling TTY (open `/dev/tty` fails) → clear error telling to use `--key-out`.

## Comments

Resolved on `vpsctl-go-rewrite` (`internal/user`). Sudoers file is `99-vpsctl-<user>`; private key emitted before pubkey install.
