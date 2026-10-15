# 11: Firewall screen — list rules

**What to build:** A Firewall screen listing every Firewall Rule (port or range, tcp/udp, source) read live from ufw or firewalld, with a column showing whether a Listening Port backs each rule. Rules added by hand outside vpsctl appear too.

**Blocked by:** 10

**Status:** resolved

- [x] Uses the existing firewall backend for both ufw and firewalld; source-limited rules show their source.
- [x] Listening Port column is correct for tcp and udp, and for ranges (any listener inside the range counts).
- [x] Firewall inactive or not installed shows a clear state instead of failing.
- [x] Tests with scripted ufw/firewalld/ss output for both backends; one `teatest` flow renders the table.

## Comments

Resolved on `feat/vpsctl-tui` @ 565909c (merge). Review fixes in b136567.
