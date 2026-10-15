# Firewall backend (ufw / firewalld)

Status: resolved
Milestone: M1
Blocked by: 01

## What
- Backend interface over ufw (debian family) and firewalld (rhel family): list Firewall Rules, add/remove a rule (port or range, tcp/udp, optional source CIDR), ensure installed + enabled.
- Used by harden now; by the TUI Firewall module in M2.

## Acceptance (tests first)
- Ensure-enabled allows the CURRENT SSH port before enabling (ufw first-enable on a port change keeps the old port reachable).
- Closing the old SSH port removes only that port's rule; unrelated rules (80/tcp, 443/tcp, source-limited rules) survive.
- `apt-get update` runs before the first apt install in a process.

## Comments

Resolved on `vpsctl-go-rewrite` (`internal/firewall`, `system.Packages`). `List` fails if firewall not installed/running — call `Ensure` before snapshot.
