# vps-hardening.sh

Multi-distro initial hardening for a freshly provisioned VPS. One bash
orchestrator + sourced modules under `lib/`, feature-detection based (no
version hardcoding), with a verify-then-cut flow designed to never lock you
out.

## What it does

1. Creates a new admin user (sudo/wheel group) with a generated **ed25519**
   key — the private key is printed **once** to your terminal, or written to
   `--key-out PATH` (chmod 600). It never touches stdout or the log file.
   The user has **no password** by design, so they get per-user sudo
   **NOPASSWD** via `/etc/sudoers.d/90-vps-hardening-<user>` — password
   sudo could never be satisfied and would lock you out of root. Security
   lives in the private key; consider adding a passphrase to your local copy.
2. SSH hardening via drop-in `/etc/ssh/sshd_config.d/00-hardening.conf`
   (first-match-wins over provider drop-ins like `50-cloud-init.conf`):
   key-only auth, no root login, optional custom port.
3. Applies changes correctly for both daemon models: classic `ssh.service` and
   **socket activation** (`ssh.socket`, Ubuntu 24.04+/Debian 13) — including a
   runtime generator probe with a manual socket drop-in fallback.
4. Locks default cloud users (`ubuntu`, `debian`, `rocky`, `cloud-user`, …):
   password lock, nologin shell, emptied `authorized_keys`, plus a cloud-init
   drop-in blocking key re-injection.
5. Firewall (ufw on Debian/Ubuntu, firewalld on RHEL-likes/openSUSE) opened
   only for the effective SSH port — also on runs without `--port`.
6. fail2ban (sshd jail, banaction matched to the real firewall backend),
   automatic security updates, and a sysctl hardening drop-in.

## Requirements

- root shell on the VPS
- **systemd as PID 1** (OpenVZ/LXC-style containers are unsupported — the
  script dies early with a clear message)

## Quick start (one command, straight from GitHub)

On the fresh VPS, as root:

```bash
curl -fsSL https://raw.githubusercontent.com/anhvandev/vps-hardening/v1.0.0/install.sh \
  | sudo bash -s -- --user myname
```

Every flag after `--` is forwarded verbatim to `vps-hardening.sh`:

```bash
# move SSH to 2222 as well
curl -fsSL https://raw.githubusercontent.com/anhvandev/vps-hardening/v1.0.0/install.sh \
  | sudo bash -s -- --user myname --port 2222

# full automation (no interactive verify gate — machine assertions still run)
curl -fsSL https://raw.githubusercontent.com/anhvandev/vps-hardening/v1.0.0/install.sh \
  | sudo bash -s -- --user myname --yes --key-out /root/mykey

# rotate a lost key
curl -fsSL https://raw.githubusercontent.com/anhvandev/vps-hardening/v1.0.0/install.sh \
  | sudo bash -s -- --user myname --rotate-key
```

How it works: `install.sh` is a thin bootstrap. It downloads the release
tarball for the tag in its URL (`v1.0.0` above), extracts it to
`/opt/vps-hardening/`, and `exec`s `vps-hardening.sh` with your arguments —
so `lib/` is present and the interactive verify gate keeps working normally.
The copy in `/opt/vps-hardening/` stays behind, handy for a later
`bash /opt/vps-hardening/vps-hardening.sh --user myname --rotate-key`.

**Always pin a tag in the URL.** Never point the one-liner at `main` — this
script rewrites sshd and firewall rules, and running unreleased code on a
production VPS is how lockouts happen.

Requirements on the VPS: root shell, `curl` (or `wget`), `tar`, and systemd as
PID 1 — all present on mainstream cloud images.

## Picking a different version (env overrides)

Mental model:

```
the URL you curl        → which install.sh code runs
VPS_HARDENING_REF=...   → which tarball gets downloaded and executed
```

`install.sh` is only a downloader (no hardening logic), so an older installer
can safely pull a newer tarball — as long as the installer itself hasn't
changed between the two tags.

```bash
# fetch a different tag than the URL's installer defaults to
curl -fsSL https://raw.githubusercontent.com/anhvandev/vps-hardening/v1.0.0/install.sh \
  | sudo VPS_HARDENING_REF=v1.0.1 bash -s -- --user myname

# test a hotfix that has landed on main but is not tagged yet (one-off only —
# unlike branch refs, tag tarballs are immutable, so prefer a tag for real use)
curl -fsSL https://raw.githubusercontent.com/anhvandev/vps-hardening/v1.0.0/install.sh \
  | sudo VPS_HARDENING_REF=main bash -s -- --user myname

# use a fork
curl -fsSL https://raw.githubusercontent.com/anhvandev/vps-hardening/v1.0.0/install.sh \
  | sudo VPS_HARDENING_REPO=you/vps-hardening bash -s -- --user myname
```

Quick reference:

| Goal | Command shape |
|---|---|
| Pinned stable release | `.../vX.Y.Z/install.sh \| sudo bash -s -- ...` |
| Different version, keep an old alias/script | add `VPS_HARDENING_REF=vX.Y.Z` after `sudo` |
| Untagged hotfix (one-off) | `VPS_HARDENING_REF=main` |
| Fork | `VPS_HARDENING_REPO=owner/repo` (+ `VPS_HARDENING_REF` if needed) |

Limits: the installer that runs is still the one from the URL — if
`install.sh` itself gets an important fix you must change the URL, env
overrides don't help. And per-version pinning is a safety feature: this
script rewrites sshd and firewall rules as root, so "always run the newest
code" is not the default on purpose.

## Usage (from a local checkout)

```bash
git clone --depth 1 --branch v1.0.0 https://github.com/anhvandev/vps-hardening.git
cd vps-hardening

bash vps-hardening.sh --user myname                    # interactive, recommended
bash vps-hardening.sh --user myname --port 2222        # also move SSH to 2222
bash vps-hardening.sh --user myname --yes --key-out /root/mykey   # automation
bash vps-hardening.sh --user myname --rotate-key       # lost the key? rotate
```

Interactive runs pause at a **verify gate**: log in from a new terminal with
the printed key (`ssh -i key -p PORT user@host`, then `sudo true`) before
password auth is disabled. Answering "no" exits safely (code 3) with password
auth untouched. `--yes` skips the human gate but still runs machine assertions
(effective pubkey auth, key file perms, sudo privileges) before locking
anything.

Flags: `--skip-firewall`, `--skip-fail2ban`, `--skip-updates`, `--skip-sysctl`.

Re-running is idempotent; a flagless re-run never reverts a previously set
custom port.

## Support matrix

**Tested** (systemd container matrix in `tests/`, run by
`tests/test-container.sh`):

| Image | Daemon model | Notes |
|---|---|---|
| ubuntu:22.04 | service | |
| ubuntu:24.04 | socket (forced) | port-change case |
| debian:12 | service | |
| debian:13 | socket (forced) | port-change case; never uses `systemctl reload` (socket bug #1128329) |
| rockylinux:9 | service + firewalld | |
| rockylinux:8 | service | OpenSSH 8.0 → `ChallengeResponseAuthentication` fallback probed at runtime |

**Expected to work** (detection covers them, not in the test matrix):
Ubuntu 25.x, Debian 11, AlmaLinux 8/9, Rocky/Alma 10, Fedora, openSUSE
Leap/Tumbleweed, Arch. openSUSE/Arch get no managed auto-update step, and Arch
has no managed firewall — both are documented skips, printed as warnings.

## SELinux caveat

The SELinux paths (`restorecon` on `~/.ssh`, `semanage port` for custom ports)
cannot be exercised in the container matrix (no enforcing policy there). The
code is written defensively (missing `semanage` downgrades to a warning), but
on an Enforcing RHEL-like system verify a custom port with
`semanage port -l | grep ssh_port_t` after the run.

## Recovery guide (locked out?)

Use your provider's web console (VNC/serial), then:

1. Edit `/etc/ssh/sshd_config.d/00-hardening.conf` — set
   `PasswordAuthentication yes` temporarily or fix the `Port` line.
2. `systemctl restart ssh` (Debian/Ubuntu) or `systemctl restart sshd`;
   on socket-activated systems `systemctl daemon-reload && systemctl restart ssh.socket`.
3. If a port change is blocked by the firewall:
   `ufw allow 22/tcp` or `firewall-cmd --add-service=ssh --permanent && firewall-cmd --reload`.

If the script stopped at the verify gate (exit 3), nothing was locked: password
auth is still enabled and default users are untouched — just SSH back in as
before.

## Development

```bash
bash tests/test-static.sh       # bash -n + shellcheck + static safety guards
bash tests/test-container.sh    # full matrix (needs docker, ~minutes)
bash tests/test-container.sh ubuntu-24.04 2222   # single target
```

Releasing a new version: see [docs/release-guide.md](docs/release-guide.md)
(tagging rules, checklist, E2E verification of the published one-liner).
