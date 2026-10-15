# 25: fail2ban — jails, bans, unban, ignore list

**What to build:** A fail2ban screen listing jails and currently banned IPs. The operator unbans an IP and adds an IP to the ignore list, with the current SSH session's IP suggested.

**Blocked by:** 09, 10

**Status:** resolved

- [x] fail2ban not installed or inactive shows a clear state.
- [x] Ignore-list change persists in vpsctl's jail drop-in and takes effect after reload; existing entries kept.
- [x] IP/CIDR validated.
- [x] Global lock + action-log line per mutation.

## Comments

Resolved on `feat/vpsctl-tui` @ f149533 (merge). Review fixes in b136567.
