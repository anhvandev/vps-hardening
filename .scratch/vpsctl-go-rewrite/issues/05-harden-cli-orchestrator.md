# `vpsctl harden` CLI orchestrator

Status: resolved
Milestone: M1
Blocked by: 02, 03, 04

## What
- Flags: `--user` (required), `--port`, `--yes`, `--key-out`, `--rotate-key`, `--skip-firewall|fail2ban|updates|sysctl`; `--port` + `--skip-firewall` rejected.
- Flow: snapshot → user + key → firewall → Stage A → apply → Verify Gate (CLI prompt on TTY; `--yes` skips) → pre-lock assertions (pubkey effective, authorized_keys 600, `sudo -n` works as the user) → Stage B → apply → close old port → lock Default Cloud Users → cloud-init → fail2ban → security-only auto updates (no auto-reboot; dnf-automatic `upgrade_type = security`) → sysctl.
- Re-run on a hardened host with no port change skips Stage A, the gate and restarts.
- Logs to `/var/log/vpsctl/harden-<ts>.log` (never the private key); exit 3 when the operator stops at the gate.

## Comments

Resolved on `vpsctl-go-rewrite` @ a44e64a (`internal/harden`). Operator "no" at Verify Gate restores pre-run SSH, then exits 3 (differs from bash). Dropped vs bash: "saved the key?" prompt, `su - user` check, fail2ban jail status check.
