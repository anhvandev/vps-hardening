# Research: Ubuntu SSH Hardening Facts for VPS Init Script (22.04 / 24.04 / 24.10+ / 25.x)

Date: 2026-08-10
Scope: facts needed to write a bash initial-hardening script (new sudo user, SSH key auth, disable password/root login) that auto-adapts across Ubuntu 22.04 LTS, 24.04 LTS, and newer releases (24.10, 25.04, 25.10).

---

## 1. SSH daemon management: service vs socket activation

### When the switch happened
- **Ubuntu 22.10 (Kinetic Kudu)** introduced systemd socket activation for sshd as the default, via `openssh-server 1:9.0p1-1ubuntu1`. Motivation: ~3 MiB RAM saved per instance.
  Source: https://discourse.ubuntu.com/t/sshd-now-uses-socket-based-activation-ubuntu-22-10-and-later/30189
- Therefore:
  - **22.04 LTS (jammy)**: traditional `ssh.service` only. OpenSSH 8.9p1.
  - **24.04 LTS (noble)**: socket activation default. OpenSSH 9.6p1.
  - **24.10 (oracular)**: socket activation, OpenSSH 9.9-era (24.10 shipped 9.9 per Plucky notes "up from 9.7 in Ubuntu 24.10" — actually Plucky notes say 25.04 has 9.9 "up from 9.7 in Ubuntu 24.10"; treat 24.10 as OpenSSH 9.7/9.9 range, socket-activated either way).
  - **25.04 (plucky)**: OpenSSH 9.9. New: `sshd.service` alias for `ssh.service` (both names valid in systemctl). Host DSA keys no longer generated.
  - **25.10 (questing)**: OpenSSH 10.0. DSA support removed entirely; PQ kex `mlkem768x25519-sha256` default; `sshd-auth` binary split; version banner `SSH-2.0-OpenSSH_10.0`.
  Sources: https://discourse.ubuntu.com/t/plucky-puffin-release-notes/48687 , https://discourse.ubuntu.com/t/questing-quokka-release-notes/59220 , https://www.openssh.org/txt/release-10.0

### Mechanics on socket-activated systems (22.10+, incl. 24.04 and all 25.x)
- `ssh.socket` owns the listening port; `sshd` starts on incoming connection. A drop-in `/etc/systemd/system/ssh.service.d/00-socket.conf` ties `ssh.service` to the socket.
- **22.10–23.10**: at package upgrade, `Port`/`ListenAddress` from sshd_config were migrated once into `/etc/systemd/system/ssh.socket.d/addresses.conf`. Editing sshd_config later had NO effect on the listening port.
- **24.04+**: migration removed. Instead a **systemd generator, `sshd-socket-generator`, parses sshd config** (including sshd_config.d drop-ins) and generates `ListenStream=` drop-ins for `ssh.socket` whenever non-default `Port`/`ListenAddress` are present. Fixed in `openssh 1:9.6p1-3ubuntu3` (noble), Launchpad bug 1991592.
  Source: https://lists.snapcraft.io/archives/foundations-bugs/2024-April/512956.html

### Correct procedure to change port / apply sshd_config changes on 24.04+ (socket systems)
Per Ubuntu maintainer Nick Rosbrook (LP #2069041, "Fix Released"):
```bash
# edit sshd_config or a drop-in, e.g. /etc/ssh/sshd_config.d/port.conf
systemctl daemon-reload        # re-runs sshd-socket-generator, regenerates socket drop-in
systemctl restart ssh.socket   # rebinds listener
```
The shipped `/etc/ssh/sshd_config` on 24.04 now carries a comment stating exactly this: after changing `Port`, `AddressFamily`, or `ListenAddress`, run `systemctl daemon-reload` (and restart `ssh.socket`).
Source: https://bugs.launchpad.net/bugs/2069041

Notes:
- Restarting `ssh.service` alone does NOT move the listening port (LP #2069041 original report).
- Non-socket directives (PasswordAuthentication, PermitRootLogin, etc.) only need the per-connection daemon to read new config — on socket systems each new connection spawns a fresh sshd instance, so `daemon-reload` + new connections pick them up; `systemctl reload ssh` / `restart ssh` also still works as a unit name (24.04), and 25.04+ accepts `sshd.service` too.
- Alternative manual override (works on all socket releases): `/etc/systemd/system/ssh.socket.d/listen.conf` with
  ```ini
  [Socket]
  ListenStream=
  ListenStream=2222
  ```
  (empty `ListenStream=` resets the list per `man systemd.socket`), then `daemon-reload` + `restart ssh.socket`. On 24.04+ prefer the sshd_config + generator path.
- To revert to classic service behavior: remove `/etc/systemd/system/ssh.service.d/00-socket.conf`, `systemctl disable --now ssh.socket`, `systemctl enable --now ssh.service`, `daemon-reload`.

### Does `systemctl reload/restart ssh` still work on 24.04+?
Yes — `ssh.service` remains a valid unit; `reload` sends SIGHUP to sshd. But it does not affect the socket's bound port; port changes require the daemon-reload + ssh.socket restart sequence above. On 25.04+ `sshd.service` is an alias of `ssh.service`.

---

## 2. sshd_config layout and precedence

### Include directive / first-match-wins
- `/etc/ssh/sshd_config` on all these releases starts with `Include /etc/ssh/sshd_config.d/*.conf` at the TOP of the file.
- `sshd_config(5)`: "Unless noted otherwise, for each keyword, the **first obtained value** will be used." Include globs expand in lexical order.
- Consequence: within `sshd_config.d`, the **lexically FIRST file that sets a keyword wins**. A `00-*.conf` beats `50-cloud-init.conf`; a `99-*.conf` LOSES to `50-cloud-init.conf`. (A popular HN/bug-thread claim that `99-local.conf` overrides `50-cloud-init.conf` is **wrong** under first-match-wins — LP #2088207 discussion and the man page confirm first-obtained-wins.)
  Sources: https://man.openbsd.org/sshd_config.5 , https://bugs.launchpad.net/cloud-init/+bug/2088207
- Verify effective values with `sshd -T` (dump effective config) rather than reasoning about files.

### Cloud-image drop-ins that fight hardening
- `/etc/ssh/sshd_config.d/50-cloud-init.conf` — written by cloud-init when the installer/datasource sets explicit ssh config; typically contains `PasswordAuthentication yes`. Present on subiquity-installed Server and many cloud images. Silently overrides `PasswordAuthentication no` in the main file (LP #2088207, HN item 42133181).
- `/etc/ssh/sshd_config.d/60-cloudimg-settings.conf` — present on some cloud images.
- cloud-init can also re-materialize settings on subsequent boots/datasources.
- **Safe override**: drop `/etc/ssh/sshd_config.d/00-hardening.conf` (or any name sorting before `50-`) with the hardening directives. Do NOT edit the main sshd_config for these keywords — drop-ins win over it anyway.

### Correct keyword values (OpenSSH 8.9–10.0)
From `sshd_config(5)`:
```
PubkeyAuthentication yes          # default yes; set explicitly for clarity
PasswordAuthentication no         # default yes
KbdInteractiveAuthentication no   # default yes; ChallengeResponseAuthentication is a deprecated alias
PermitRootLogin no                # default prohibit-password (key-only root)
UsePAM yes                        # Ubuntu default; keep yes
```
UsePAM interplay: with `UsePAM yes`, PAM auth is reachable via BOTH `PasswordAuthentication` and `KbdInteractiveAuthentication`; man page: "you should disable either PasswordAuthentication or KbdInteractiveAuthentication" — for hardening disable BOTH, otherwise keyboard-interactive password login still works even with `PasswordAuthentication no`.
Source: https://man7.org/linux/man-pages/man5/sshd_config.5.html

---

## 3. User creation on Ubuntu cloud images

### adduser vs useradd
- Ubuntu Server docs recommend **`adduser`** (Debian-family high-level tool): creates home from /etc/skel, sets up group, prompts for password.
  Source: https://ubuntu.com/server/docs/how-to/security/user-management/
- Non-interactive script pattern:
  ```bash
  adduser --disabled-password --gecos "" "$USER"   # no password, no prompts
  # or fully explicit:
  useradd -m -s /bin/bash -c "" "$USER"
  ```
  `adduser --disabled-password` avoids the interactive password prompt pitfall. Locking the password does NOT block SSH key login (key auth bypasses the password field); Ubuntu docs explicitly warn locking a password doesn't stop key-based login — which is exactly what we want.
- Home dir perms: Ubuntu 21.10+ default `0750` (`drwxr-x---`). Fine for SSH.
- Add to sudo group: `adduser "$USER" sudo` or `usermod -aG sudo "$USER"`. The `sudo` group is authorized in /etc/sudoers by default on Ubuntu.

### Default `ubuntu` user
- Cloud images ship user `ubuntu` (uid 1000, in sudo group), password locked, keys injected by cloud-init.
- Disabling/locking it after your new admin user is verified:
  - `usermod -L ubuntu` (lock password — cosmetic; already locked) and, more effective, `usermod -s /usr/sbin/nologin ubuntu` or remove its `~/.ssh/authorized_keys`.
  - Risk: on cloud images, cloud-init may re-manage the default user on reboot/datasource refresh (it can re-add keys). To fully neutralize, either remove authorized_keys AND set nologin shell, or configure cloud-init (`/etc/cloud/cloud.cfg.d/`) to not recreate — heavier. Minimal-risk recommendation: keep the account but strip its authorized_keys and set nologin shell after the new user is verified.
  - Do NOT `deluser --remove-home ubuntu` blindly: some provider tooling assumes the default user exists.

### authorized_keys setup
```bash
install -d -m 700 -o "$USER" -g "$USER" "/home/$USER/.ssh"
install -m 600 -o "$USER" -g "$USER" /path/to/pubkey "/home/$USER/.ssh/authorized_keys"
```
- sshd `StrictModes yes` (default) requires: home not group/world-writable, `.ssh` 700, `authorized_keys` 600, owned by the user.
- SELinux: not used on Ubuntu (AppArmor is); no `restorecon` needed. AppArmor does not restrict sshd's file reads here. No extra MAC step required on stock Ubuntu.

---

## 4. Safe rollout pattern (lockout avoidance)

Recommended order:
1. Create new sudo user + install authorized_keys (section 3).
2. (Optional, if changing port) configure new port in drop-in, `systemctl daemon-reload && systemctl restart ssh.socket` (24.04+) or `systemctl restart ssh` (22.04); open firewall first (`ufw allow <port>/tcp`).
3. **Verify from a SECOND terminal**: `ssh -i key -p <port> user@host` works AND `sudo -v` works. Keep the original root session open.
4. Only then write hardening drop-in `/etc/ssh/sshd_config.d/00-hardening.conf` with PasswordAuthentication/KbdInteractiveAuthentication/PermitRootLogin.
5. Validate: `sshd -t` (syntax check; on socket systems run as root: `sshd -t` needs host keys readable) and inspect effective config `sshd -T | grep -Ei 'passwordauthentication|permitrootlogin|kbdinteractive|pubkey'`.
6. Apply: `systemctl daemon-reload && systemctl restart ssh.socket` (socket systems) or `systemctl reload ssh` / `restart ssh` (22.04).
7. Final verify with a THIRD fresh connection before closing the original session.

Session-survival facts:
- Traditional sshd restart: existing sessions survive (each connection is its own forked sshd process; restart only affects the listener/parent).
- Socket activation: each accepted connection spawns a per-connection instance (`ssh@.service` template instances exist on noble — LP #2111226, #2110468). Restarting `ssh.socket` only rebinds the listener; established sessions run in their own instances and are unaffected. Same for `restart ssh.service`. So the "keep current session, test new one" pattern remains safe on 24.04+.
- `sshd -t` caveat: returns nonzero if it can't read host keys (run as root). Under socket activation there may be no persistent sshd process — `sshd -t` still works as a config validator regardless of activation mode.

---

## 5. Version/socket detection strategy in bash

```bash
# OS + version
. /etc/os-release            # ID=ubuntu, VERSION_ID="24.04", VERSION_CODENAME=noble
[ "$ID" = "ubuntu" ] || exit 1

# Socket activation in use? (runtime-truth, better than version compare)
if systemctl list-unit-files ssh.socket &>/dev/null && \
   systemctl is-enabled ssh.socket &>/dev/null; then
    SOCKET=1
fi
# even more direct: systemctl is-active ssh.socket
```
- Prefer **feature detection over version parsing**: check for `ssh.socket` unit existence + enabled/active state. This also handles systems where an admin reverted to `ssh.service`.
- The generator (`/usr/lib/systemd/system-generators/sshd-socket-generator`) exists on 24.04+; its presence implies "edit sshd_config, daemon-reload, restart ssh.socket" is the right flow. On 22.10–23.10 (socket but no generator) the manual `ssh.socket.d/*.conf` ListenStream override is needed — but those interim releases are EOL and out of script scope (22.04 LTS → service; 24.04+ → generator).
- Branch summary for the script:
  - `ssh.socket` enabled/active → socket path (24.04, 24.10, 25.x): port change via sshd_config drop-in + `daemon-reload` + `restart ssh.socket`.
  - else → service path (22.04): port change in drop-in + `systemctl restart ssh`.

---

## 6. 25.04 / 25.10 specifics that affect hardening

- **25.04 (OpenSSH 9.9)**:
  - `PerSourcePenalties` new option (penalizes sources failing auth repeatedly) — on by default upstream with sane defaults; no script action needed, but note it exists (can cause "connection refused" during brute-force-ish testing; tune via `PerSourcePenalties`/`PerSourcePenaltyExemptList` if scripted tests fail).
  - `sshd.service` alias added — `systemctl restart sshd` now works.
  - Host DSA keys no longer generated.
- **25.10 (OpenSSH 10.0)**:
  - DSA algorithm support fully removed.
  - Default kex is post-quantum `mlkem768x25519-sha256`; finite-field DH (`diffie-hellman-group*`, group-exchange) no longer in default server KEX list — old clients (e.g. GCE ssh-in-browser) break. Script should not hardcode legacy kex.
  - `sshd-auth` binary split (packaging handled by Ubuntu; logs may show `sshd-auth`).
  - Banner is `SSH-2.0-OpenSSH_10.0` — do not match `OpenSSH_1*` for version checks.
  - `DisableForwarding` bug fix; `Match version` support; globs allowed in AuthorizedKeysFile.
- No changes to socket activation model in 25.04/25.10; 24.04 procedure applies.

---

## Script design implications

1. **Write one drop-in, never edit main file**: `/etc/ssh/sshd_config.d/00-hardening.conf` — name must sort BEFORE `50-cloud-init.conf` because sshd uses first-obtained-value wins. Contents:
   ```
   PubkeyAuthentication yes
   PasswordAuthentication no
   KbdInteractiveAuthentication no
   PermitRootLogin no
   ```
2. **Feature-detect, don't version-compare**: branch on `systemctl is-enabled/is-active ssh.socket`, not on `VERSION_ID`. This covers 22.04 (service), 24.04+/25.x (socket+generator), and hand-reverted systems.
3. **Port change procedure**:
   - socket path: write `Port N` into the same drop-in (or a `00-port.conf`), then `systemctl daemon-reload && systemctl restart ssh.socket`. Do NOT rely on `restart ssh` to move the port.
   - service path (22.04): same drop-in, `systemctl restart ssh`.
   - open UFW for the new port before restarting the listener; delete port 22 rule only after verifying.
4. **User creation**: `adduser --disabled-password --gecos "" NAME && adduser NAME sudo`; install keys with `install -d -m700` / `install -m600` owned by the user. Keep UsePAM yes.
5. **Anti-lockout order**: user+keys → (port change + verify) → hardening drop-in → `sshd -t` → apply → verify new session → only then touch the `ubuntu` user (strip authorized_keys + `usermod -s /usr/sbin/nologin`, don't delete). Always keep one known-good root/admin session open until a fresh login is proven.
6. **Validation**: `sshd -t` for syntax, `sshd -T` for effective values (catches cloud-init drop-in precedence surprises).
7. **25.x awareness**: don't emit DSA/legacy-kex config; expect `PerSourcePenalties` to throttle repeated failed logins during testing; `sshd` unit alias available on 25.04+ but `ssh` name works everywhere.

---

Status: DONE_WITH_CONCERNS
Summary: All core facts verified against Ubuntu Discourse announcements, Launchpad bugs (1991592, 2069041, 2088207, 2111226), openssh release notes, and man pages: socket activation began 22.10, 24.04 added the sshd-socket-generator (port changes need `daemon-reload` + `restart ssh.socket`), sshd_config.d uses first-match-wins so hardening drop-ins must sort before `50-cloud-init.conf`, and 25.04/25.10 bring OpenSSH 9.9/10.0 (PerSourcePenalties, DSA removal, PQ kex) without changing the socket model.
Concerns/Blockers: The exact OpenSSH version in 24.10 (9.7 vs 9.9) was not pinned to a changelog entry — immaterial since behavior is identical for this script's scope. Session-survival during `ssh.socket` restart is inferred from the per-connection `ssh@.service` instance model (confirmed to exist on noble via LP #2111226/#2110468) plus standard systemd Accept=yes semantics, not from an explicit Canonical doc.

Unresolved questions:
- Exact openssh package version shipped in Ubuntu 24.10 GA (9.7 vs 9.9) — both Plucky note phrasing and changelog should be checked if precision matters.
- Whether any cloud provider images still ship `60-cloudimg-settings.conf` with hardening-relevant keys on 24.04+ (image-specific; script should `ls /etc/ssh/sshd_config.d/` and warn).
