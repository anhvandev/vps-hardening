# 16: Users screen — list Managed Users

**What to build:** A Users screen listing Managed Users (UID ≥ 1000 with a login shell) with sudo yes/no, number of authorized keys, locked yes/no, and the operator's own user marked. System accounts are hidden.

**Blocked by:** 10

**Status:** ready-for-agent

- [ ] Sudo state reflects the per-user passwordless rule vpsctl manages and admin-group membership.
- [ ] Locked state covers both password lock and nologin shell.
- [ ] Tests with fixture passwd/group/sudoers and scripted commands; one `teatest` render.
