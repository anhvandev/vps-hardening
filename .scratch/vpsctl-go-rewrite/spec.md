# vpsctl — Go rewrite with management TUI

Status: ready-for-agent

Rewrite the bash one-shot hardening script as `vpsctl`: a single Go binary (bubbletea TUI) run as root on one VPS, doing initial Hardening and ongoing management. See `docs/adr/0001-go-tui-full-rewrite.md` and `GLOSSARY.md` for vocabulary.

## Decisions (from grilling session, 2026-10-15)

### Shape
- One tool. `sudo vpsctl` opens the TUI; `sudo vpsctl harden --user X [--port N] [--yes] [--key-out P] [--rotate-key] [--skip-*]` is the non-interactive CLI path.
- Full rewrite in Go; bash implementation is deleted (no wrapping). No compatibility with bash v1.0.0 state — no server runs it.
- Runs on the VPS itself, one machine at a time. No remote/multi-host.
- Live system is the source of truth: read `ufw`/`firewalld`/`systemctl`/`passwd` each time. Only persist what the system cannot know (e.g. key-emitted markers).
- Supported: Ubuntu 22.04/24.04, Debian 12/13, Rocky/Alma 8/9. suse/arch: best-effort, no dedicated code.
- UI language: English.
- Name: repo + binary `vpsctl`. Paths: `/usr/local/bin/vpsctl`, `/var/lib/vpsctl`, `/var/log/vpsctl/`, `/run/vpsctl.lock`.

### Distribution
- GitHub Actions on tag builds `linux-amd64` + `linux-arm64` static binaries + sha256 sums.
- `install.sh` downloads the right arch, verifies sha256, installs to `/usr/local/bin/vpsctl`, then (optionally) forwards args to `vpsctl harden`.
- `vpsctl self-update`: fetch latest release, verify sha256, replace binary. TUI only notifies of new versions.

### Safety
- Lockout Guard is a hard block in the TUI, no override. Blocks: acting on the current session's user, or leaving zero usable Admin Users (sudo + key + unlocked); closing the SSH port; enabling a firewall without the SSH port allowed. Applies the same on SSH or provider console.
- Protected Units: ssh/sshd (.service/.socket), ufw, firewalld, systemd-networkd/NetworkManager, systemd-resolved, cloud-init → no stop/disable/edit/delete. Restart allowed except ssh (SSH module owns that). fail2ban: stop/start allowed, unit edit blocked.
- SSH port change always via the two-stage flow with Verify Gate; SSH module has no switches that weaken Hardening (no password auth / root login toggles).
- Global lock `/run/vpsctl.lock` for every mutating action; reads are free. Second session sees "locked by <user> (pid N)".
- Action log: `/var/log/vpsctl/actions.log`, one line per mutation (time, `SUDO_USER`, action, result). Never logs private keys. TUI has a viewer.

### Modules
- **Overview**: open Firewall Rules, fail2ban state, auto-update last run / pending / reboot-required, disk/RAM, red "not hardened" banner + shortcut to the Hardening wizard (other modules stay usable).
- **Firewall**: drive ufw (Debian/Ubuntu, installed by Hardening if missing) / firewalld (Rocky/Alma). Firewall Rule = port or range + tcp/udp + optional source IP/CIDR. No ufw app profiles. Column shows whether a Listening Port exists.
- **SSH**: port change (two-stage + Verify Gate); effective config (`sshd -T`) with Match-overridden lines flagged; active sessions.
- **Users**: Managed Users only (UID ≥ 1000, login shell). Create / delete / lock; grant/revoke per-user NOPASSWD sudo; keys: paste a public key or generate a pair. Always key-only, never a password.
- **Services**: systemd `.service`; default filter running/enabled/failed, toggle show-all, name filter; start/stop/restart/enable/disable; journal with follow. Edit existing units via drop-in override (`<unit>.d/override.conf`, revertable) in `$EDITOR` (default nano), then `systemd-analyze verify` + `daemon-reload`; on failure don't apply, offer re-edit. Create via form (Name, Description, ExecStart, User — non-root by default, WorkingDirectory, Restart, Environment) with "Advanced" → `$EDITOR`; then offer enable + start.
- **Timers**: list with next run; edit/create via the same mechanism (form: OnCalendar + target Service).
- **Cron**: crontabs of root + Managed Users: view/add/edit/delete Cron Entries.
- **fail2ban**: jails, banned IPs, unban, add IP to `ignoreip` (suggest current SSH session IP). No manual ban / jail tuning.
- **Actions log** viewer.
- Hardening keeps: auto updates **security-only, no auto-reboot**, sysctl drop-in. sysctl/Docker/web-server modules are v2.

### Private key display
- On generation the TUI leaves the alternate screen, prints the raw key (no borders), waits for the operator to type `saved`, then returns. Alternative choice: write to a file (mode 600). Never logged.

### Testing
- System access goes through a mockable command runner; Go unit tests need no root.
- Each safety invariant has its own test (open-new-before-close-old, rollback, Lockout Guard).
- Container matrix (Ubuntu 22.04/24.04, Debian 12/13, Rocky 8/9) runs the real binary via `vpsctl harden`.
- TUI: `teatest` on a few main flows only.
- The 5 critical bugs from the bash review get failing tests first, then fixes.

### Bash review bugs that must not be re-introduced
1. ufw first enable on a port change only allowed the new port → old port blocked; rollback then left zero SSH ports open.
2. Closing the old SSH port deleted every numeric tcp allow rule (80, 443, …).
3. Port change on an already-hardened host rewrote the drop-in without auth hardening, then died without rollback.
4. Only the sshd-apply failure rolled back; any other failure after mutation left half-applied config.
5. sudo was ensured after sudoers files were written → failed on images without sudo.
Also: reject existing system users (UID < 1000) as admin; clean up generated private key on every failure path; detect a real controlling TTY (open it), not file permissions; `apt-get update` before first install.

## Milestones (each one a usable release)
- **M1** core + `vpsctl harden` CLI, container matrix green, release pipeline + install.sh, bash removed. → `issues/`
- **M2** TUI shell: Overview, Firewall, SSH, Hardening wizard.
- **M3** Users, Services/Timers, Cron.
- **M4** fail2ban, Actions log viewer, self-update.

## Cleanup (M1)
- Delete `vps-hardening.sh`, `lib/`, `tests/test-static.sh`. Keep `tests/Dockerfile.*` (reused for the Go binary). Keep `plans/` as history. Rewrite `README.md` and `docs/release-guide.md`.
