# 16: Users screen — list Managed Users

**What to build:** A Users screen listing Managed Users (UID ≥ 1000 with a login shell) with sudo yes/no, number of authorized keys, locked yes/no, and the operator's own user marked. System accounts are hidden.

**Blocked by:** 10

**Status:** resolved

- [x] Sudo state reflects the per-user passwordless rule vpsctl manages and admin-group membership.
- [x] Locked state covers both password lock and nologin shell.
- [x] Tests with fixture passwd/group/sudoers and scripted commands; one `teatest` render.

## Comments

Resolved on `feat/vpsctl-tui` @ 3c18362 (merge). Review fixes in b136567.
