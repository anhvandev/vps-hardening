# 09: Shared global lock and action log

**What to build:** The global mutation lock and the action log move out of the CLI entry point into a shared module, so the TUI can take the same lock and record the same action lines. `vpsctl harden` behaves exactly as before.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] One module owns: take the global lock (holder = real login name from `SUDO_USER`, else root, plus pid), report the holder when the lock is busy, append one action-log line (time, operator, action, result).
- [ ] `vpsctl harden` uses it; existing CLI tests (including the lock-holder message) still pass unchanged.
- [ ] Lock and log behaviour covered by tests that use a temp directory (no root needed).
- [ ] Private keys can never reach the action log (the API takes only an action label and a result).
