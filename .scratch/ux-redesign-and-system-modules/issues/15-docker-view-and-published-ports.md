# 15: Docker screen (read-only) and Published Port warnings

**What to build:** When Docker is installed, a Docker screen (design §7) lists containers grouped by compose project with state, ports and image; Published Ports bound to all interfaces are flagged. The Firewall screen shows each Published Port as a row marked "bypasses firewall" with the fix guidance and a link to the container. Overview's Security card gains a Docker line. Without Docker the menu item is hidden.

**Blocked by:** 03

**Status:** ready-for-agent

- [ ] Ports bound to 127.0.0.1/::1 are not flagged.
- [ ] vpsctl never modifies Docker's firewall rules.
- [ ] Unit tests with scripted docker output (with and without compose labels); `teatest`: Firewall shows the Published Port row.
