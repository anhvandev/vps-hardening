# 17: Contract — remove the old mutation path and ad-hoc UI

**What to build:** With every screen on Tasks and shared widgets, delete the old pieces: direct mutation helper calls from screens, per-screen status lines, hand-rolled y/n prompts, lists and forms. Behaviour is unchanged.

**Blocked by:** 05, 06, 07, 08, 09, 10

**Status:** resolved

- [x] No screen mutates the host except through a Task.
- [x] No screen renders its own confirm prompt or table.
- [x] Full test suite and container matrix green.

## Comments

Resolved on `feat/ux-redesign` @ c1234b4 (merge). Code-review fixes in aa00873.
