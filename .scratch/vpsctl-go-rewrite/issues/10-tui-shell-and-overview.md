# 10: TUI shell and Overview screen

**What to build:** `sudo vpsctl` with no subcommand opens a bubbletea TUI: a module menu, keyboard navigation, quit, and a read-only Overview showing Firewall Rules, fail2ban state, automatic-update status (last run, pending updates, reboot required), disk and RAM. On a host that is not hardened, a red banner says so (with a shortcut slot for the Hardening wizard, wired in 15); other modules stay reachable.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] Root + systemd preflight runs before the TUI opens; failure prints a clean error.
- [ ] Overview reads everything live through the existing command seam each time it is shown; nothing is cached to disk.
- [ ] "Not hardened" is derived from the live SSH state (Stage B not live).
- [ ] Missing pieces (fail2ban not installed, firewall inactive) render as a state, not an error.
- [ ] `teatest` covers: Overview render on a hardened host, banner on an unhardened host, quit.
- [ ] Container matrix still green; menu entries for modules not yet built are hidden or marked "coming soon".
