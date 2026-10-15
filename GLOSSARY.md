# VPS Management

A tool run as root on a single VPS that performs initial hardening and then manages the machine's firewall, users, services and SSH access through a TUI.

## Language

**Hardening**:
The one-time initial lockdown of a fresh VPS: admin user with key-only SSH, password and root login disabled, firewall on, default cloud users locked.
_Avoid_: Setup, provisioning, install

**Admin User**:
The key-only account created by Hardening that the operator logs in as; holds passwordless sudo.
_Avoid_: Operator account, main user

**Managed User**:
A human login account (UID ≥ 1000 with a login shell) shown and managed by the tool; always key-only, never has a password.
_Avoid_: Account, system user

**Default Cloud User**:
A login account pre-created by the cloud image (e.g. `ubuntu`, `ec2-user`) that Hardening locks.
_Avoid_: Image user

**Firewall Rule**:
An allow entry made of a port or port range, a protocol (tcp/udp), and an optional source IP/CIDR.
_Avoid_: Open port (when you mean the rule), app profile

**Listening Port**:
A port a local process is actually bound to, independent of whether a Firewall Rule allows it.
_Avoid_: Open port (when you mean the socket)

**Service**:
A systemd `.service` unit on the machine, whether shipped by a package or created by the operator.
_Avoid_: Daemon, app, process

**Timer**:
A systemd `.timer` unit that schedules a Service.
_Avoid_: Scheduled task, cron (when you mean a timer)

**Cron Entry**:
One line in a user's crontab (root or a Managed User).
_Avoid_: Job, task

**Protected Unit**:
A unit whose loss would cut remote access or the firewall (ssh, ufw/firewalld, networking, resolver, cloud-init); the Lockout Guard forbids stopping, disabling, editing or deleting it.
_Avoid_: System service, critical service

**Lockout Guard**:
The rule that the TUI refuses any action that would cut the operator's own SSH path (closing the SSH port, stopping sshd, locking the Admin User, revoking own sudo).
_Avoid_: Safety check, confirmation

**Verify Gate**:
The pause after the SSH change is live but before password auth is disabled, where the operator proves a new login works.
_Avoid_: Confirmation step
