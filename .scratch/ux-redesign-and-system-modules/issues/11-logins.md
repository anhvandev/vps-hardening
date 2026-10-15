# 11: Logins screen

**What to build:** A read-only Logins screen (design §9): successful SSH logins (user, source IP, time) and failed attempts for the last 24 h, toggle to 7 days, with the top failing IPs and the operator's own session marked. Overview's Security card gains a "Logins 24h: N ok · M failed" line that opens it.

**Blocked by:** 03

**Status:** resolved

- [x] Works on Ubuntu/Debian and Rocky/Alma log sources, including hosts without a syslog file (journal only).
- [x] No actions on this screen (no ban button).
- [x] Unit tests over fixture journal output for both families; `teatest` render and window toggle.

## Comments

Resolved on `feat/ux-redesign` @ c7340c7 (merge). Code-review fixes in aa00873.
