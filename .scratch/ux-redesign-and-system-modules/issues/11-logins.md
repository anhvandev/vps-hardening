# 11: Logins screen

**What to build:** A read-only Logins screen (design §9): successful SSH logins (user, source IP, time) and failed attempts for the last 24 h, toggle to 7 days, with the top failing IPs and the operator's own session marked. Overview's Security card gains a "Logins 24h: N ok · M failed" line that opens it.

**Blocked by:** 03

**Status:** ready-for-agent

- [ ] Works on Ubuntu/Debian and Rocky/Alma log sources, including hosts without a syslog file (journal only).
- [ ] No actions on this screen (no ban button).
- [ ] Unit tests over fixture journal output for both families; `teatest` render and window toggle.
