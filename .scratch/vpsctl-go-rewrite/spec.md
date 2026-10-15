# vpsctl — Go rewrite with a management TUI

Status: ready-for-agent

## Problem Statement

The operator provisions a fresh VPS and runs a bash script once to harden it. After that, every routine task — opening or closing a port, adding a teammate, restarting or creating a Service, checking fail2ban, editing cron — means remembering and typing distro-specific commands (`ufw` vs `firewall-cmd`, `adduser` vs `useradd`, sudoers syntax, systemd drop-ins) by hand. That is inconvenient, error-prone, and some mistakes (closing the SSH port, stopping sshd, revoking your own sudo) lock the operator out of the machine. The current script also carries known lockout bugs (see Further Notes).

## Solution

`vpsctl`: one Go binary installed on the VPS. `sudo vpsctl` opens a polished TUI to see the machine's state and manage firewall, SSH, users, Services, Timers, cron and fail2ban, with a Lockout Guard that refuses any action that would cut the operator's own SSH path. `sudo vpsctl harden ...` runs initial Hardening non-interactively for automation. Everything reads the live system, so changes made by hand show up immediately. The bash implementation is retired (ADR-0001).

## User Stories

### Install & update
1. As an operator, I want to install vpsctl on a fresh VPS with one `curl | sudo bash` command, so that I don't need git or a toolchain.
2. As an operator, I want the installer to pick the right binary for my CPU architecture (amd64/arm64), so that it works on any common VPS.
3. As an operator, I want the installer to verify the binary's sha256 and refuse on mismatch, so that a tampered download never runs as root.
4. As an operator, I want the installer to forward hardening arguments, so that install + Hardening is still one command.
5. As an operator, I want `vpsctl self-update`, so that I can upgrade without re-running the installer.
6. As an operator, I want the TUI to tell me when a newer release exists without updating on its own, so that upgrades stay under my control.
7. As an operator, I want `vpsctl version`, so that I know what I'm running.

### Hardening
8. As an operator, I want `vpsctl harden --user NAME` to create an Admin User with a generated ed25519 key, so that I get key-only access immediately.
9. As an operator, I want the private key shown exactly once as raw text outside the TUI frame, so that I can copy it cleanly.
10. As an operator, I want the option to write the private key to a file with mode 600 instead, so that automation and non-TTY runs work.
11. As an operator, I want a clear error telling me to use a key file when there is no real terminal, so that the key is never silently lost.
12. As an operator, I want Hardening to refuse if a key is installed but was never emitted, unless I ask to rotate it, so that nobody ends up with an unknown credential.
13. As an operator, I want `--rotate-key` to regenerate, reinstall and re-emit the key, so that I can recover a lost key.
14. As an operator, I want Hardening to refuse `root`, Default Cloud User names and existing system accounts as the Admin User, so that I never grant root-equivalent access to a service account.
15. As an operator, I want the Admin User to get passwordless sudo, so that a key-only account can still escalate.
16. As an operator, I want sudo installed before any sudoers rule is written, so that Hardening works on minimal images.
17. As an operator, I want SSH optionally moved to a custom port, so that I cut log noise from scanners.
18. As an operator, I want the old SSH port to stay reachable through the firewall until the new port is proven, so that I'm never locked out mid-change.
19. As an operator, I want a Verify Gate that asks me to log in from a new terminal before password auth is disabled, so that I prove access before the point of no return.
20. As an operator, I want to stop safely at the Verify Gate, with password auth still on and default users untouched, so that I can fix things and resume later.
21. As an automation user, I want `--yes` to skip the human gate while machine assertions (pubkey effective, authorized_keys perms, sudo works for the user) still run, so that CI hardening is safe.
22. As an operator, I want password auth, keyboard-interactive auth and root login disabled after the gate, so that only keys work.
23. As an operator, I want any failure after the first change to restore the pre-run state, so that a half-applied config never remains.
24. As an operator, I want a re-run on a hardened host to change nothing and skip the gate, so that Hardening is idempotent.
25. As an operator, I want a port change on an already-hardened host to keep auth hardening intact, so that re-running never weakens security.
26. As an operator, I want Default Cloud Users locked and cloud-init prevented from re-injecting their keys, so that image backdoors are closed.
27. As an operator, I want the firewall enabled with only my SSH port allowed on a fresh host, so that the machine ends firewalled.
28. As an operator, I want fail2ban installed with an sshd jail matching the real firewall backend, so that brute force gets banned.
29. As an operator, I want automatic security-only updates with no automatic reboot, so that patches land without surprise downtime or feature upgrades.
30. As an operator, I want a sysctl hardening drop-in applied, so that common network attacks are mitigated.
31. As an operator, I want a timestamped Hardening log that never contains the private key, so that I can audit what happened.
32. As an operator, I want Hardening to work on both classic and socket-activated SSH, so that Ubuntu 24.04 and Debian 13 behave correctly.
33. As an operator on Rocky/Alma, I want SELinux taught about a custom SSH port, so that sshd can bind it.

### TUI shell & Overview
34. As an operator, I want `sudo vpsctl` to open a TUI, so that I manage the VPS without remembering commands.
35. As an operator, I want an Overview screen with Firewall Rules, fail2ban state, update status (last run, pending, reboot required), disk and RAM, so that I see machine health at a glance.
36. As an operator on a host not yet hardened, I want a red banner with a shortcut to the Hardening wizard while other modules stay usable, so that I can inspect before hardening.
37. As an operator, I want the Hardening wizard in the TUI to collect the same inputs as the CLI and walk me through the Verify Gate, so that interactive Hardening is guided.
38. As an operator, I want a second concurrent TUI session to still read everything but be told who holds the lock when it tries to change something, so that two admins never race.
39. As an operator, I want every mutating action recorded with time, my real login name, the action and its result, so that changes are auditable.
40. As an operator, I want a screen to browse that action log, so that I can see who changed what.

### Firewall
41. As an operator, I want to list Firewall Rules with port/range, protocol and source, so that I know what is exposed.
42. As an operator, I want each rule marked with whether a Listening Port backs it, so that I spot rules nobody uses.
43. As an operator, I want to open a port or port range for tcp or udp, so that I can expose a new app quickly.
44. As an operator, I want to restrict a rule to a source IP/CIDR, so that databases are reachable only from trusted hosts.
45. As an operator, I want to remove a Firewall Rule, so that I can close what I no longer need.
46. As an operator, I want removing a rule to touch only that rule, so that unrelated rules (80, 443…) survive.
47. As an operator, I want the Lockout Guard to refuse closing the SSH port, so that I can't cut my own access.
48. As an operator, I want rules I add by hand with ufw/firewall-cmd to appear in the TUI, so that the TUI never disagrees with the machine.

### SSH
49. As an operator, I want to change the SSH port from the TUI through the same two-stage flow and Verify Gate, so that port changes are safe interactively.
50. As an operator, I want to view the effective sshd config with lines overridden by Match blocks flagged, so that I understand what really applies.
51. As an operator, I want to see active SSH sessions, so that I know who is logged in.
52. As an operator, I want the SSH screen to offer no switch that re-enables password or root login, so that the tool never weakens Hardening.

### Users
53. As an operator, I want to list Managed Users with sudo, key count and lock state, so that I know who can get in.
54. As an operator, I want to create a Managed User that is key-only, so that teammates get access without passwords.
55. As an operator, I want to add a key by pasting an existing public key, so that teammates keep their own private keys.
56. As an operator, I want to generate a keypair for a user and see the private key once, so that I can onboard someone without a key.
57. As an operator, I want to remove a single key from a user, so that I can revoke one device.
58. As an operator, I want to grant or revoke passwordless sudo per user, so that I control privilege.
59. As an operator, I want to lock or unlock a user, so that I can suspend access without deleting data.
60. As an operator, I want to delete a user, choosing whether to keep the home directory (kept by default), so that I don't lose data by accident.
61. As an operator, I want the Lockout Guard to refuse locking, deleting or revoking sudo of my own session's user, so that I can't lock myself out.
62. As an operator, I want the Lockout Guard to refuse any change that would leave zero usable Admin Users (sudo + key + unlocked), so that the machine always has a way in.
63. As an operator, I want system accounts hidden from the Users screen, so that I only see humans.

### Services & Timers
64. As an operator, I want to list Services filtered to running/enabled/failed by default, with a toggle for all and a name filter, so that the list stays readable.
65. As an operator, I want to start, stop, restart, enable and disable a Service, so that I manage apps without systemctl.
66. As an operator, I want to view a Service's journal with live follow, so that I can debug it.
67. As an operator, I want to edit a packaged Service through an override (not the vendor file), so that package upgrades don't erase my changes.
68. As an operator, I want to revert an override, so that I can undo customizations.
69. As an operator, I want edits opened in my `$EDITOR` (nano by default), so that I use a real editor.
70. As an operator, I want edits verified before reload and not applied if invalid, with a chance to re-edit, so that a typo never breaks a Service.
71. As an operator, I want to create a new Service from a form (name, description, command, user, working directory, restart policy, environment), so that I deploy an app without writing unit syntax.
72. As an operator, I want new Services to default to a non-root user, so that apps don't run as root by accident.
73. As an operator, I want an "Advanced" option that opens the generated unit in my editor, so that I can use any directive.
74. As an operator, I want to be offered enable + start after creating a Service, so that it's live in one go.
75. As an operator, I want Protected Units refused for stop/disable/edit/delete (and ssh refused for restart), so that I can't kill remote access or the firewall.
76. As an operator, I want fail2ban stoppable/startable but its unit not editable, so that I can pause it without breaking it.
77. As an operator, I want to list Timers with their next run time, so that I see scheduled work.
78. As an operator, I want to create or edit a Timer (schedule + target Service) with the same verify-before-apply behaviour, so that scheduling is safe.

### Cron
79. As an operator, I want to view root's and each Managed User's Cron Entries, so that I see legacy scheduled jobs.
80. As an operator, I want to add, edit and delete Cron Entries, so that I manage cron without `crontab -e`.
81. As an operator, I want an invalid schedule rejected before saving, so that a crontab is never corrupted.

### fail2ban
82. As an operator, I want to see jails and currently banned IPs, so that I know what fail2ban is doing.
83. As an operator, I want to unban an IP, so that I can rescue a blocked teammate.
84. As an operator, I want to add an IP to the ignore list with my current SSH session IP suggested, so that I never ban myself.

### Distros
85. As an operator on Ubuntu 22.04/24.04, Debian 12/13 or Rocky/Alma 8/9, I want every feature to work, so that I can rely on it.
86. As an operator on another distro, I want a clear "best-effort" warning, so that I know I'm off the supported path.
87. As an operator on a host without systemd as PID 1 or not running as root, I want a clean early error, so that nothing is half-done.

## Implementation Decisions

- **Shape**: single static Go binary `vpsctl`; bubbletea for the TUI. No subcommand → TUI; `harden`, `self-update`, `version` subcommands. CLI parsing with the standard library.
- **System seam (as built in M1)**: every command goes through a `Runner` (args → stdout, stderr, exit code; a scripted `Fake` records calls). Files are read/written for real under a configurable root directory, so tests point it at a temp dir. No module calls the host any other way.
- **Live system is the source of truth**: no desired-state store. Only data the system can't know is persisted (key-emitted markers).
- **Modules** (each a deep module with a small public surface over the system seam):
  - *Detection*: distro/family, SSH unit + socket mode + actual socket unit, SELinux, admin group, package manager; root + systemd preflight.
  - *Firewall*: one backend interface, two implementations (ufw for the debian family — installed if missing — and firewalld for the rhel family). Operations: list rules, add/remove a Firewall Rule (port or range, tcp|udp, optional source CIDR), ensure enabled while keeping a given SSH port allowed. No ufw app profiles.
  - *SSH*: two-stage drop-in (Stage A = port only; Stage B = port + auth hardening), Include check, foreign `Port` neutralization, validation via `sshd -t`/`-T`/`-T -C`, apply for service and socket models (never `reload`), SELinux port labelling, field-exact listener checks, snapshot/rollback covering drop-ins, main config, socket drop-in and firewall rules. Stage choice is derived from current state: if Stage B is live, a port change writes Stage B.
  - *Users*: Managed Users = UID ≥ 1000 with a login shell. Create (key-only, never a password), delete (keep home by default), lock/unlock, per-user passwordless sudo validated with `visudo` and installed atomically (ordered after any group rule), key add/remove/generate, Default Cloud User locking, cloud-init re-injection block.
  - *Services/Timers*: list/filter, lifecycle actions, journal with follow, override drop-ins edited in `$EDITOR`, `systemd-analyze verify` + `daemon-reload` before apply, create from form with generated unit, revert override.
  - *Cron*: per-user crontab read/write for root and Managed Users, with schedule validation.
  - *fail2ban*: jails, banned IPs, unban, ignoreip edit.
  - *Lockout Guard*: pure decision function over a snapshot of the relevant system facts (session user, Admin Users and their sudo/key/lock state, SSH port, Protected Units) and a proposed action → allow or refuse with a reason. Hard block, no override. Same behaviour on SSH or provider console.
  - *Hardening orchestrator*: snapshot → Admin User + key → firewall (allow current SSH port first) → Stage A → apply → Verify Gate → pre-lock assertions → Stage B → apply → close only the old SSH port's rule → lock Default Cloud Users → cloud-init → fail2ban → security-only updates (no auto-reboot) → sysctl. Any failure after the first mutation triggers rollback. Exit code 3 when the operator stops at the gate. Shared by the CLI and the TUI wizard.
  - *Action log + global lock*: every mutating action takes a global lock (holder name + pid shown to others) and appends one action-log line (time, `SUDO_USER`, action, result). Reads never lock. Private keys are never logged.
  - *Releases*: self-update and the installer fetch release binaries and a sha256 list and fail closed on mismatch.
- **Private key emission**: the TUI leaves the alternate screen, prints the raw key, waits for the operator to type `saved`, then returns; alternative is a 600 file. A real controlling TTY is detected by opening it, not by file permissions. Generated key material is removed on every exit path.
- **Package installs**: refresh package lists before the first install in a process.
- **Distribution**: CI on `v*` tags runs tests, builds `linux-amd64` and `linux-arm64` with CGO disabled, and publishes binaries + sha256 list. Installer picks arch, verifies, installs to `/usr/local/bin/vpsctl`, and forwards args to `vpsctl harden` when given.
- **Naming & paths**: repo and binary `vpsctl`; state under `/var/lib/vpsctl`, logs under `/var/log/vpsctl/`, lock at `/run/vpsctl.lock`. No compatibility with bash v1 state (no server runs it).
- **Supported distros**: Ubuntu 22.04/24.04, Debian 12/13, Rocky/Alma 8/9; others best-effort with no dedicated code.
- **UI language**: English.

## Testing Decisions

- **Good tests exercise external behaviour only**: enter through a module's public operations with the fake `Runner` and a temp root dir, then assert on observable outcomes — resulting file contents, which Firewall Rules remain, which commands ran and in what order, the returned error/refusal. Never assert on internal helpers or private state.
- **Modules tested through the fake `Runner` + temp root**: Detection, Firewall, SSH, Users, Services/Timers, Cron, fail2ban, Hardening orchestrator, action log/lock. Lockout Guard is tested as a pure function with fact snapshots (no seam at all).
- **One dedicated test per safety invariant**: new SSH port allowed before the old is closed (command order); old SSH port reachable during first firewall enable; closing the old port leaves unrelated rules; Stage B never downgraded on port change; rollback on failure at every post-mutation step; rollback never leaves zero SSH ports allowed; sudo installed before sudoers written; system accounts rejected as Admin User; key material removed on failure; Lockout Guard refusals (own user, last usable Admin User, SSH port, Protected Units).
- **Red first**: tests for the five bash-review lockout bugs are written failing before the code that fixes them.
- **Container matrix**: the real binary runs `vpsctl harden` in privileged systemd containers for all six supported images. Prior art: the existing `tests/test-container.sh` and `tests/Dockerfile.*` (effective sshd config, listener checks, idempotent re-run, rotate-key, firewall state). New scenarios: port change on a hardened host, image without sudo, pre-existing `80/tcp` rule survives a port change, forced apply failure leaves the old port allowed and listening.
- **TUI**: `teatest` on a handful of main flows (Overview render, open a port, Lockout Guard refusal shown, Hardening wizard through the gate) using the fake `Runner` + temp root underneath. No exhaustive UI tests.
- Unit tests must pass without root.

## Out of Scope

- Remote / multi-host management; any agent or inventory.
- suse and arch dedicated code paths.
- Password-based logins for any user; switches that re-enable password or root SSH login.
- ufw application profiles; nftables-direct backend.
- Manual fail2ban bans and jail tuning (bantime, maxretry).
- sysctl management module, Docker, web-server management (v2).
- Lockout Guard overrides / force flags.
- Automatic self-update; automatic reboots after updates.
- Localization (UI is English only).
- Migration from bash v1.0.0 state.

## Further Notes

- Delivered in milestones, each a usable release: **M1** core + `vpsctl harden` CLI, container matrix green, release pipeline + installer, bash removed; **M2** TUI shell with Overview, Firewall, SSH, Hardening wizard; **M3** Users, Services/Timers, Cron; **M4** fail2ban, action-log viewer, self-update. Tickets live in `issues/`: 01–08 = M1 (done), 09–15 = M2, 16–24 = M3, 25–27 = M4.
- Lockout bugs found in the bash review that must not return: (1) first ufw enable on a port change allowed only the new port, and rollback then left no SSH port open; (2) closing the old SSH port deleted every numeric tcp allow rule; (3) a port change on a hardened host rewrote the drop-in without auth hardening, then died without rollback; (4) only sshd-apply failures rolled back; (5) sudo was ensured after sudoers files were written.
- Repo cleanup in M1: delete the bash script, its libs and the static test; keep the Dockerfiles and `plans/` history; rewrite README and release guide; rename the GitHub repo to `vpsctl` (manual step).
- See ADR-0001 and `GLOSSARY.md`.
