# 10: Task History screen

**What to build:** "Action log" becomes "Task History" (menu and screen). It lists Tasks newest first (time, operator, Task, result) with a text filter; selecting one opens its full output in a viewport.

**Blocked by:** 02, 03

**Status:** ready-for-agent

- [ ] Entries written before this change (no output file) still list, with "no output recorded".
- [ ] Large histories load a bounded tail.
- [ ] `teatest`: list, filter, open an output.
