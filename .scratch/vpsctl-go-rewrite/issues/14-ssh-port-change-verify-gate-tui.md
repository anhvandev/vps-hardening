# 14: SSH — change port from the TUI with the Verify Gate

**What to build:** From the SSH screen the operator changes the SSH port. vpsctl runs the existing two-stage change (new port allowed in the firewall first, Stage A applied, Verify Gate, Stage B, old port's rule removed), with the Verify Gate as a TUI dialog showing the exact `ssh -p <port> <user>@<host>` command and "Login works" / "Stop safely" choices. Stopping restores the pre-change state.

**Blocked by:** 12, 13

**Status:** ready-for-agent

- [ ] Reuses the existing SSH change flow; no second implementation of staging or rollback.
- [ ] Holds the global lock for the whole change; writes action-log lines for start and outcome.
- [ ] Any failure after the first mutation restores the snapshot; the TUI shows what was restored.
- [ ] Lockout Guard refuses a port already used by another Listening Port.
- [ ] `teatest`: successful change through the gate; "Stop safely" path leaves the old port allowed and listening (scripted).
