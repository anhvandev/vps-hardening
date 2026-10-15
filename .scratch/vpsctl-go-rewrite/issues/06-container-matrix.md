# Container matrix for the Go binary

Status: resolved
Milestone: M1
Blocked by: 05

## What
- Reuse `tests/Dockerfile.*`; build static `vpsctl` and mount it. Port the assertions of the old `tests/test-container.sh` (effective sshd config, listener, idempotent re-run, rotate-key, firewall state).
- New scenarios: port change on an already-hardened host; image without sudo; pre-existing `80/tcp` ufw rule survives a port change; forced apply failure → old port still allowed + listening.

## Acceptance
- Full matrix green: Ubuntu 22.04/24.04, Debian 12/13, Rocky 8/9.

## Comments

Resolved on `vpsctl-go-rewrite` @ d2a1f9d. Matrix green on all 6 distros: `bash tests/test-container.sh [distro port]`. Bugs fixed: 3dadb81 (socket restart must stop running ssh.service first), 8994455 (`/run/sshd` before `sshd -T`).
