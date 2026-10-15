# 13: SSH screen — effective config and active sessions

**What to build:** An SSH screen showing the effective sshd configuration (port, auth settings, root login) with lines that a Match block overrides flagged, plus the list of active SSH sessions (user, source IP, since). No switch on this screen can weaken Hardening.

**Blocked by:** 10

**Status:** resolved

- [x] Effective values come from the live daemon; Match-overridden settings are detected by comparing the global result with the per-user probe for Managed Users.
- [x] Active sessions list includes the operator's own session, marked as such.
- [x] Tests with scripted `sshd -T` / session output, including a Match block that re-enables password auth.

## Comments

Resolved on `feat/vpsctl-tui` @ b587102 (merge). Review fixes in b136567.
