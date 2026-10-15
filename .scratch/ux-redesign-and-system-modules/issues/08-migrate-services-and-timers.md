# 08: Move Services and Timers onto Tasks and shared widgets

**What to build:** Services (design §6) and Timers on the shared widgets; start/stop/restart/enable/disable, edit override, revert, create Service/Timer all run as Tasks. Journal view uses the shared viewport with wheel scroll and follow. Services auto-refresh every 5 s while visible. Protected Units show ◆ and disabled buttons with the reason.

**Blocked by:** 03

**Status:** ready-for-agent

- [ ] The `$EDITOR` hand-off and verify-before-apply behave as today.
- [ ] Filter dropdown (running·enabled·failed / all) and `/` name filter work with keyboard and mouse.
- [ ] `teatest`: restart as a Task; refused stop of ssh; journal follow; refresh tick.
