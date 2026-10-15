# 04: Hardening Record and Hardening Status (read-only)

**What to build:** Every Hardening run (CLI or TUI) saves a Hardening Record: when it ran, the Admin User, and which Hardening Steps the operator chose to skip. On a hardened machine the Hardening screen is the Hardening Status table (design §2a): each Hardening Step read live as Done / Missing / Skipped, with "was applied <date>" when the Record says a now-Missing step was done. On an unhardened machine the screen shows the wizard (§2b). The header badge becomes `Hardening x/y`: red when SSH is not key-only, yellow when other steps are Missing.

**Blocked by:** 03

**Status:** ready-for-agent

- [ ] Live checks exist for every step: Admin User + key, key-only SSH + no root login, SSH port, firewall on, Default Cloud Users locked, cloud-init re-injection block, fail2ban, automatic security updates, sysctl.
- [ ] No Record (hardened by hand or Record lost) still shows Done/Missing from live checks; Skipped needs the Record.
- [ ] The Record never stores secrets; written atomically.
- [ ] Unit tests: each step's detection over fake command output + temp root; Missing vs Skipped vs "was applied" combinations. `teatest`: hardened and unhardened renders, badge colors.
