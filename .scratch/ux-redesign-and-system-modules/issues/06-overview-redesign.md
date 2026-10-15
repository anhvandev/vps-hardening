# 06: Overview redesign

**What to build:** Overview as four cards (design §1): Security (Hardening x/y with what's missing, SSH, Firewall), Resources (CPU, RAM, Disk with bars, uptime), Updates (pending counts, last auto-run, reboot required), Services (running count, failed units by name, Timers that missed their last run). Every card and every warning is clickable and opens the matching screen or item. Auto-refresh every 5 s while visible, with "refreshed Ns ago".

**Blocked by:** 03, 04

**Status:** resolved

- [x] Cards for modules added later (Docker, Logins, Swap) are lines each of those tickets adds; this ticket leaves room for them.
- [x] Missing data (fail2ban not installed, no updates info) shows as a state, never an error.
- [x] `teatest`: render, click a failed Service opens it, refresh tick updates values (tick injected, no real waiting).

## Comments

Resolved on `feat/ux-redesign` @ 80eb18a (merge). Code-review fixes in aa00873.
