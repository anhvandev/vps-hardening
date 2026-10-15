# 11: Firewall screen — list rules

**What to build:** A Firewall screen listing every Firewall Rule (port or range, tcp/udp, source) read live from ufw or firewalld, with a column showing whether a Listening Port backs each rule. Rules added by hand outside vpsctl appear too.

**Blocked by:** 10

**Status:** ready-for-agent

- [ ] Uses the existing firewall backend for both ufw and firewalld; source-limited rules show their source.
- [ ] Listening Port column is correct for tcp and udp, and for ranges (any listener inside the range counts).
- [ ] Firewall inactive or not installed shows a clear state instead of failing.
- [ ] Tests with scripted ufw/firewalld/ss output for both backends; one `teatest` flow renders the table.
