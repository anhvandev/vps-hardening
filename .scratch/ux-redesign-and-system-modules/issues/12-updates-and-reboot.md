# 12: Updates screen and reboot

**What to build:** An Updates screen (design §9) listing pending packages (current → new, security or other) and reboot-required state. `[ Install security ]` (normal confirm) and `[ Install all … ]` (dangerous confirm) run as Tasks with live package-manager output. `[ Reboot … ]` requires typing `reboot` and is refused while another session holds the global lock.

**Blocked by:** 02, 03

**Status:** ready-for-agent

- [ ] Security-only selection is correct on apt and dnf.
- [ ] Package lists are refreshed before listing/installing.
- [ ] Reboot writes its Task History entry before the machine goes down.
- [ ] Unit tests with scripted apt/dnf output; `teatest`: install security as a Task, reboot confirm, reboot refused while locked.
