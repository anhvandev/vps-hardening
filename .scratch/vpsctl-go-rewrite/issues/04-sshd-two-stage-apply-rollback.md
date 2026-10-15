# sshd two-stage drop-in, apply, rollback

Status: resolved
Milestone: M1
Blocked by: 01, 03

## What
- Drop-in `/etc/ssh/sshd_config.d/00-vpsctl.conf`. Stage A = Port only; Stage B = Port + PasswordAuthentication no, KbdInteractive/ChallengeResponse no, PubkeyAuthentication yes, PermitRootLogin no.
- Include directive check, foreign `Port` neutralization, `sshd -t`/`sshd -T`/`sshd -T -C` validation, Match block warnings.
- Apply for service and socket models (generator probe + manual socket drop-in in the right `<socket-unit>.d`), SELinux `ssh_port_t`, field-exact listener verification. Never `reload`.
- Snapshot covers drop-ins, main config, socket drop-in, firewall rules.

## Acceptance (tests first)
- Port change on a host where Stage B is live writes Stage B with the new port (never downgrades auth).
- ANY failure after the first mutation (validation, apply, firewall) restores the snapshot — not only apply failures.
- Rollback never removes the rule for the pre-run SSH port and never leaves zero SSH ports allowed.

## Comments

Resolved on `vpsctl-go-rewrite` @ 729e862 (`internal/sshd`: Begin → StageA → StageB, Restore). Orchestrator must call `Restore` for its own failures between stages.
