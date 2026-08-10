# Cook report: vps-hardening-script

**Date:** 2026-08-10 | **Plan:** plans/260810-0051-vps-hardening-script (5/5 phases, 38/38 tasks) | **Mode:** --auto | **Review verdict:** SHIP (code-reviewer, 2 rounds)

## What shipped

```
vps-hardening.sh   orchestrator (flags, lock-safe two-stage flow, verify gate)
lib/logging.sh     info/warn/err/die, TTY colors, ask_yesno via /dev/tty
lib/detect.sh      os-release → FAMILY/SSH_UNIT/SOCKET_MODE/SELINUX/ADMIN_GROUP/PKG; systemd+root preflight
lib/user.sh        create_admin_user, install/rotate_user_key (ed25519, /dev/tty or --key-out), lock_default_users, wheel sudoers, cloud-init 99-hardening.cfg
lib/sshd.sh        two-stage 00-hardening.conf, sshd -t/-T/-C validate, socket generator probe + manual fallback, snapshot/rollback (incl. firewall rules), field-exact verify_listener
lib/firewall.sh    ufw/firewalld; setup unconditional; open-before-apply / close-after-verify split
lib/services.sh    fail2ban (banaction matched to backend), unattended-upgrades/dnf-automatic, sysctl drop-in
tests/             test-static.sh (bash -n, shellcheck, grep guards, source-safety), test-container.sh (6-image systemd matrix), 6 Dockerfiles
README.md          usage, tested-vs-expected matrix, SELinux caveat, recovery guide
```

## Verification evidence

- shellcheck -S warning: clean (10 files)
- bash -n: clean
- Static guards: no `reload ssh`, 00- drop-in only, field-exact `ss -ltnH "sport = :"`, libs source-safe under `set -euo pipefail`
- Container matrix **6/6 pass**: ubuntu:22.04, ubuntu:24.04 (socket, --port 2222), debian:12, debian:13 (socket, --port 2222), rockylinux:9, rockylinux:8 (OpenSSH 8.0 → ChallengeResponseAuthentication fallback confirmed)
- Per image asserted: pre-state socket mode, sshd -T 3 values + port, sshd -T -C probe, key login via localhost ssh, password auth refused, firewall opens only effective port, port 22 closed after change, fail2ban functional ban materializes in backend, auto-update timer, run-2 idempotent, flagless re-run keeps custom port, log free of private key
- Gate-decline (exit 3) + pre-lock assertions: by code review walk

## Bugs caught by the matrix (fixed)

1. `sshd -T | grep -q` SIGPIPE under pipefail → capture output first
2. `mv` over existing file returns 1 on EL8 coreutils → `cat >` write
3. `scan_match_blocks` last-statement exit-status landmine → explicit `return 0`
4. fail2ban Ubuntu 22.04: no rsyslog → `backend = systemd`; f2b 0.11.2 has no nftables action → `iptables-multiport` fallback
5. Ubuntu 24.04: `sshd -t` fails on missing /run/sshd pre-first-start → ensure_hostkeys creates it

## Post-review fixes (code-reviewer H1/H2/M3/M4, all verified round 2)

- H1: `--skip-firewall` + `--port` rejected at flag parse (lockout gap)
- H2: snapshot/rollback now covers firewall allow-rules (conservative purge: only post-snapshot ports, never old_port)
- M3: ufw purge strips ` (v6)` rows
- M4: locale-tolerant ufw active grep

## Open items (accepted, documented)

- SELinux (restorecon/semanage): manual verification on a real VM still pending — README records the caveat; container cannot enforce
- From-restricted ufw tuples outside purge reach (pre-existing limitation, documented)

## Unresolved questions

None.
