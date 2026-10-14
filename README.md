# vpsctl

One static Go binary that hardens a freshly provisioned VPS. Run it as root
on the VPS itself. It reads the live system (sshd, ufw/firewalld, systemd)
on every run and uses a verify-then-cut flow so you never get locked out.

M1 ships the non-interactive `vpsctl harden` command. Running `vpsctl` with
no arguments only prints a placeholder; the management TUI is not built yet.

## What `vpsctl harden` does

1. Creates the **Admin User** (sudo/wheel group) with a generated ed25519
   key. The private key is printed **once** to the controlling TTY, or
   written to `--key-out PATH` (mode 600). It is never logged. The user has
   no password, so they get per-user sudo NOPASSWD
   (`/etc/sudoers.d/99-vpsctl-<user>`).
2. Firewall: ufw (Debian/Ubuntu, installed if missing) or firewalld
   (Rocky/Alma). It allows the SSH port before enabling the firewall.
   Existing rules (80, 443, …) are kept.
3. SSH: drop-in `/etc/ssh/sshd_config.d/00-vpsctl.conf`. It sets key-only
   auth, no root login and an optional new port. A port change is done in
   two stages: open the new port, pass the **Verify Gate**, then close the
   old port. Works with both `ssh.service` and socket-activated `ssh.socket`.
   If a step fails, the previous SSH config is restored.
4. Locks **Default Cloud Users** (`ubuntu`, `debian`, `rocky`, …) and stops
   cloud-init from putting their keys back.
5. Sets up fail2ban (sshd jail), automatic security-only updates (no
   auto-reboot) and a sysctl drop-in (`/etc/sysctl.d/90-vpsctl.conf`).

Running it again on an already-hardened host is safe. With no port change,
it skips the SSH restart and the Verify Gate.

## Install

On the VPS, as root:

```bash
curl -fsSL https://raw.githubusercontent.com/anhvandev/vpsctl/v2.0.0/install.sh \
  | sudo bash -s -- --user myname
```

`install.sh` downloads `vpsctl-linux-<amd64|arm64>` and `sha256sums.txt`
from the GitHub release, checks the sha256 (it stops on any mismatch) and
installs the binary to `/usr/local/bin/vpsctl`. Any arguments after `--` are
passed to `vpsctl harden`. With no arguments it only installs.

**Always pin a tag in the URL**, never `main`. This tool rewrites sshd and
firewall rules as root.

Env overrides:

| Variable | Default | Purpose |
|---|---|---|
| `VPSCTL_VERSION` | the tag pinned in `install.sh` | release to download |
| `VPSCTL_BASE_URL` | `https://github.com/anhvandev/vpsctl/releases/download` | download base (forks, mirrors) |
| `VPSCTL_BIN_DIR` | `/usr/local/bin` | install directory |

Requirements: root, systemd as PID 1, `curl` or `wget`, `sha256sum`.

## Usage

```
vpsctl harden --user NAME [--port N] [--yes] [--key-out PATH] [--rotate-key]
              [--skip-firewall] [--skip-fail2ban] [--skip-updates] [--skip-sysctl]
vpsctl version
```

```bash
sudo vpsctl harden --user myname                    # interactive, recommended
sudo vpsctl harden --user myname --port 2222        # also move SSH to 2222
sudo vpsctl harden --user myname --yes --key-out /root/mykey   # automation
sudo vpsctl harden --user myname --rotate-key       # lost the key? rotate
```

- **Verify Gate**: in an interactive run, vpsctl stops and asks you on the
  TTY. Before you answer, log in from a new terminal with the new key
  (`ssh -i key -p PORT user@host`, then `sudo true`). If you answer "no",
  the old SSH config is restored and nothing is locked.
- `--yes` skips this prompt. vpsctl still checks that sshd accepts pubkey
  auth for the user, that `authorized_keys` has mode 600 and that `sudo -n`
  works for the user before it locks anything.
- You cannot use `--port` together with `--skip-firewall`.

Exit codes: `0` ok, `1` error, `2` usage, `3` stopped at the Verify Gate.

Files: run log `/var/log/vpsctl/harden-<timestamp>.log`, action log
`/var/log/vpsctl/actions.log`, lock `/run/vpsctl.lock` (only one mutating
run at a time).

## Supported distros

Tested in the container matrix: Ubuntu 22.04/24.04, Debian 12/13,
Rocky 8/9. AlmaLinux 8/9 uses the same code path. Other distros (openSUSE,
Arch, …) get a warning and run best-effort.

SELinux: on Enforcing hosts a custom port is labeled with `semanage port`.
This path is not covered by the container matrix, so check it with
`semanage port -l | grep ssh_port_t`.

## Recovery (locked out?)

Open your provider's web console (VNC/serial), then:

1. Edit `/etc/ssh/sshd_config.d/00-vpsctl.conf`: fix the `Port` line, or
   set `PasswordAuthentication yes` for a short time.
2. `systemctl restart ssh` (Debian/Ubuntu) or `systemctl restart sshd`.
   On socket-activated systems run
   `systemctl daemon-reload && systemctl restart ssh.socket`.
3. If the firewall blocks the port: `ufw allow 22/tcp`, or
   `firewall-cmd --add-service=ssh --permanent && firewall-cmd --reload`.

## Development

```bash
go test ./...                                   # unit tests, no root needed
bash tests/test-install.sh                      # install.sh against a fake release
bash tests/test-container.sh                    # full container matrix (docker)
bash tests/test-container.sh ubuntu-24.04 2222  # single image, first run with --port
```

Releasing: see [docs/release-guide.md](docs/release-guide.md).
