# 26: Action log viewer

**What to build:** A screen to browse the action log newest-first (time, operator, action, result), with a text filter.

**Blocked by:** 09, 10

**Status:** ready-for-agent

- [ ] Reads the log written by the shared module from 09; missing log shows "no actions yet".
- [ ] Large logs load a bounded tail.
- [ ] One `teatest` render with fixture lines.
