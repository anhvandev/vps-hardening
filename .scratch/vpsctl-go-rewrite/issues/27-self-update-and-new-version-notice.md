# 27: Self-update and new-version notice

**What to build:** `sudo vpsctl self-update` downloads the latest release binary for this architecture plus the sha256 list, verifies it (fail closed), and replaces the installed binary atomically. The TUI shows a non-blocking notice when a newer release exists; it never updates on its own.

**Blocked by:** 10

**Status:** ready-for-agent

- [ ] Checksum mismatch or download failure leaves the current binary untouched.
- [ ] Same asset names and checksum file as the installer.
- [ ] Version check failure (offline) is silent in the TUI.
- [ ] Takes the global lock; action-log line with old → new version.
