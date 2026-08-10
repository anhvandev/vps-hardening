# Research Report: SSH Hardening Differences Across Linux Distros & Versions

- **Conducted:** 2026-08-10
- **Scope:** Debian 11/12/13, RHEL-family 8/9/10 (Rocky/Alma), Fedora, openSUSE, Arch, cloud-image default users, SELinux, firewalld vs UFW
- **Companion:** [Ubuntu research](research-260810-0028-ubuntu-ssh-hardening.md)

## Executive Summary

VPS hardening script must branch on **3 SSH daemon models**, not 2: (a) classic `ssh.service`/`sshd.service` managing its own port; (b) systemd **socket activation** where PID 1 owns the listener (Ubuntu ≥22.10 incl. 24.04+, Debian 13 fresh installs, Armbian); (c) distros that *rejected/removed* socket activation (Fedora removed `sshd.socket` in F40, RHEL-family never adopted it). Feature-detection (`systemctl list-unit-files ssh.socket` + `is-active`) beats version parsing everywhere. Second axis: **config-override mechanism** — Debian/Ubuntu use `sshd_config.d/*.conf` with first-match-wins (drop-in must sort before `50-cloud-init.conf`); RHEL-family uses same include dir but adds **crypto-policies** layer that can reject algorithm overrides; on RHEL-family **SELinux** requires `restorecon` on new `~/.ssh`. Third axis: **default cloud user name** differs per distro (`ubuntu`, `debian`, `rocky`, `almalinux`, `cloud-user`, `fedora`, `arch`, `ec2-user`).

## Key Findings

### 1. SSH daemon management model by distro/version

| Distro | Release | Model | Reload/restart gotcha |
|---|---|---|---|
| Ubuntu | 22.04 | `ssh.service` | `systemctl restart ssh` |
| Ubuntu | 22.10+, 24.04, 24.10, 25.x | **`ssh.socket`** (socket activation); `sshd-socket-generator` reads sshd_config → generates `ListenStream` drop-ins | Port change: `daemon-reload && restart ssh.socket`; `restart ssh.service` does NOT move port |
| Debian | 11, 12 | `ssh.service` | Standard |
| Debian | **13 (trixie), fresh install** | **`ssh.socket` active by default** (upgrades from 12 keep `ssh.service`) | `systemctl reload ssh` → SIGHUP → sshd tries to rebind port owned by systemd → `fatal: Cannot bind any address`, service FAILED (Debian bug #1128329). Use `restart`, not `reload`. |
| Fedora | ≤39 | `sshd.service` default; `sshd.socket` opt-in | — |
| Fedora | **40+** | `sshd.socket` unit **removed entirely** (BZ#2025716) | Only `sshd.service` exists; socket users were locked out on upgrade |
| RHEL/Rocky/Alma | 8, 9, 10 | `sshd.service` (no socket activation adoption) | Standard; note `sshd.service` name, not `ssh.service` |
| openSUSE | Leap/Tumbleweed | `sshd.service` | Standard |
| Arch | rolling | `sshd.service` default; socket activation only via AUR opt-in | Standard |

**Implication:** unit name differs too — Debian/Ubuntu = `ssh`, RHEL/Fedora/openSUSE/Arch = `sshd`. Script must resolve both name AND activation mode at runtime.

### 2. sshd_config.d precedence (all distros with openssh ≥ 8.7-ish)

- All modern releases ship `Include /etc/ssh/sshd_config.d/*.conf` at TOP of sshd_config → **first-obtained value wins** → hardening drop-in must be named `00-*.conf`, NOT `99-*.conf`.
- Cloud-init writes `50-cloud-init.conf` (often `PasswordAuthentication yes`) on Ubuntu, Debian, RHEL-family cloud images. Some provider images ship additional drop-ins (e.g. `60-cloudimg-settings.conf`) — script should LIST `/etc/ssh/sshd_config.d/` and warn on unknown files.
- RHEL-family extra layer: **system-wide crypto-policies** (`/etc/crypto-policies/back-ends/opensshserver.config`) included via drop-in. RHEL 9/10 DEFAULT policy disables SHA-1 in SSH (except HMAC), DSA, 3DES, FFDHE-1024; custom `Ciphers`/`MACs`/`HostKeyAlgorithms` in sshd_config can CONFLICT with policy. Either use `update-crypto-policies --set LEGACY` (weakens everything — not recommended) or drop-in sub-policy modules; simplest: don't override algorithms on RHEL, let DEFAULT policy rule.

### 3. Auth keyword changes across versions

- `PasswordAuthentication no` + `KbdInteractiveAuthentication no` both required (UsePAM yes routes passwords through both) — universal.
- `PermitRootLogin`: RHEL 9+ already defaults to disabling root **password** login (prohibit-password behavior); script should still set explicit `PermitRootLogin no` everywhere.
- DSA: gone ≥ OpenSSH 9.8 (Ubuntu 25.x, Debian 13, Fedora 40+, RHEL 10) — use ed25519 for key generation everywhere; rsa-4096 fallback only if targeting very old clients.
- `~/.pam_environment` no longer read by sshd on Debian 13 (and OpenSSH ≥ 9.8 generally drops pam_env user file) — don't rely on it.
- Ubuntu 25.04+/OpenSSH 9.9: `PerSourcePenalties` on by default — scripted repeated login tests may get throttled.
- OpenSSH 10.0 (Ubuntu 25.10, Fedora 43, Debian 13 ships 10.0p1): PQ kex default, finite-field DH dropped, `sshd-auth` binary split — no hardening-script impact, but `sshd -T` output parsing still fine.

### 4. Default cloud-image users (lock target list)

| Distro | Default user |
|---|---|
| Ubuntu | `ubuntu` |
| Debian | `debian` |
| RHEL / CentOS (generic) | `cloud-user` |
| CentOS (some images) | `centos` |
| Rocky | `rocky` |
| AlmaLinux | `almalinux` |
| Fedora | `fedora` |
| openSUSE | `opensuse` |
| Arch | `arch` |
| Amazon Linux | `ec2-user` |
| Oracle Linux | `opc` |
| FreeBSD | `freebsd` |

**Implication:** lock logic must detect which of these exists (`id -u <name>`), not hardcode `ubuntu`. Lock = strip `authorized_keys` + `usermod -L` + `usermod -s /usr/sbin/nologin`; don't `userdel` (cloud-init may re-manage).

### 5. User creation per distro

- Debian/Ubuntu: `adduser --disabled-password --gecos "" NAME`; sudo group = `sudo`.
- RHEL-family/Fedora/openSUSE/Arch: `useradd -m -s /bin/bash NAME`; admin group = **`wheel`** (not `sudo`). On RHEL wheel needs no sudoers edit (enabled by default); Arch requires ensuring `%wheel` line uncommented in sudoers.
- Keys: `install -d -m700 -o U -g U ~U/.ssh` + `install -m600 ...` universal.

### 6. SELinux (RHEL-family, Fedora) — critical difference

- After creating `~/.ssh`/`authorized_keys` manually, MUST run `restorecon -Rv ~USER/.ssh` or key auth silently fails with correct permissions (classic `ssh-keygen`-vs-manual-copy trap).
- Detect: `command -v getenforce && [ "$(getenforce)" != "Disabled" ]`.
- Debian/Ubuntu: AppArmor present, no action needed for ssh keys.
- Changing SSH port on SELinux systems ALSO needs `semanage port -a -t ssh_port_t -p tcp <port>` (package `policycoreutils-python-utils`) or sshd won't bind — Ubuntu/AppArmor needs nothing.

### 7. Firewall & fail2ban & auto-updates per distro

| Concern | Debian/Ubuntu | RHEL-family/Fedora | openSUSE | Arch |
|---|---|---|---|---|
| Firewall tool | `ufw` (also `nftables` directly) | **`firewalld`** (default, running on cloud images) | firewalld | none default |
| Open SSH port (custom P) | `ufw allow P/tcp && ufw enable` | `firewall-cmd --permanent --add-port=P/tcp --remove-service=ssh && firewall-cmd --reload` (or edit ssh service port) | same as RHEL | iptables/nftables manual |
| fail2ban install | `apt install fail2ban` (works out of box, sshd jail on) | `dnf install fail2ban` — needs **EPEL** on Rocky/Alma; backend should be `systemd` (no /var/log/auth.log; RHEL logs sshd to journal) | zypper, systemd backend | pacman, systemd backend |
| fail2ban jail config | `/etc/fail2ban/jail.d/local.conf` | same path; set `backend = systemd`, `banaction = firewallcmd-rich-rules` or `nftables` | same | same |
| Auto updates | `unattended-upgrades` | `dnf-automatic` (`systemctl enable --now dnf-automatic.timer`) | `yast2-online-update-configuration` or zypper cron | none (manual) |

**RHEL gotcha:** fail2ban default config assumes Debian log paths — without `backend = systemd` the sshd jail never bans. On firewalld systems prefer `banaction = firewallcmd-ipset`/`rich-rules`.

### 8. Reload-vs-restart safety matrix

| System | Safe after config change |
|---|---|
| Ubuntu 22.04 / Debian ≤12 / RHEL / openSUSE / Arch | `systemctl reload ssh[d]` or `restart` — both fine |
| Ubuntu ≥24.04 socket mode | `daemon-reload && restart ssh.socket` for port; `reload ssh` OK only for non-port config; NEVER `reload` expecting rebind |
| Debian 13 socket mode | `reload` BROKEN (rebind conflict) — use `restart ssh` (socket keeps listening, sessions survive via per-connection `ssh@.service`) |

Universal safety: `sshd -t` validate → `sshd -T -C user=...,host=...,addr=...` check effective config → restart → keep current session open → verify NEW session + sudo before locking defaults.

## Implementation Recommendations

### Detection order in script

```bash
. /etc/os-release                      # ID, VERSION_ID, ID_LIKE
FAMILY=debian; [[ "$ID_LIKE $ID" =~ rhel|fedora ]] && FAMILY=rhel
SSH_UNIT=ssh; [[ $FAMILY == rhel || $ID =~ fedora|opensuse|arch ]] && SSH_UNIT=sshd
SOCKET_MODE=false
systemctl list-unit-files ssh.socket sshd.socket &>/dev/null && \
  systemctl is-active --quiet ssh.socket 2>/dev/null || \
  systemctl is-active --quiet sshd.socket 2>/dev/null && SOCKET_MODE=true
SELINUX=false; command -v getenforce &>/dev/null && [ "$(getenforce)" != Disabled ] && SELINUX=true
```

### Distro-branch summary for script design

1. **User:** adduser (debian) vs useradd+wheel (rhel/arch).
2. **Keys:** + `restorecon` if SELINUX.
3. **Drop-in `00-hardening.conf`:** universal path `/etc/ssh/sshd_config.d/`; verify dir exists (very old openssh lacks Include — RHEL 8 has it since 8.x openssh 8.0, fine).
4. **Port change:** + `semanage port` if SELINUX; restart socket if SOCKET_MODE else restart service.
5. **Firewall:** ufw (debian) vs firewalld (rhel/opensuse); skip if neither installed (Arch).
6. **fail2ban:** install; write jail.d drop-in with `backend=systemd` on non-Debian; EPEL needed on Rocky/Alma (`dnf install epel-release`).
7. **Updates:** unattended-upgrades vs dnf-automatic.
8. **Lock default user:** iterate candidate list per table §4.
9. **Verify-then-cut:** mandatory before locking defaults.

## Resources & References

- Debian 13 release notes issues: https://www.debian.org/releases/trixie/release-notes/issues.en.html
- Debian 13 socket reload bug #1128329 + claudiokuenzler.com/blog/1522 analysis
- Fedora socket removal: github.com/coreos/fedora-coreos-tracker/issues/1558, BZ#2025716
- RHEL 9 security changes: redhat.com/en/blog/security-features-red-hat-enterprise-linux-9; RHEL 9/10 crypto-policies docs
- Default cloud users: docs.openstack.org/image-guide/obtain-images.html
- SELinux authorized_keys: access.redhat.com/solutions/3948421, serverfault.com/q/849631
- fail2ban on Rocky 10: computingforgeeks.com/install-fail2ban-rocky-almalinux/

## Unresolved Questions

- Exact openssh version enabling `ssh.socket` by default on Debian 13 fresh installs (behavior confirmed, package version unpinned).
- SLES default cloud user (`opensuse` vs `ec2-user` per provider) — treat as candidate list entry.
- Whether all Rocky/Alma minimal images include firewalld pre-installed (script should no-op if absent rather than install unconditionally — needs decision).
