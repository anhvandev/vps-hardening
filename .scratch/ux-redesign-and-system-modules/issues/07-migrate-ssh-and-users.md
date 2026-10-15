# 07: Move SSH and Users onto Tasks and shared widgets

**What to build:** SSH and Users screens look like the design (§5 for Users) and every mutation is a Task. The SSH port change runs as a Task with the Verify Gate in the Task panel. Deleting a user uses the dangerous confirm (type the name, home kept by default); other user actions use the normal confirm. The operator's own user is marked `(you)` and its guarded actions are disabled with the reason.

**Blocked by:** 03

**Status:** resolved

- [x] No behaviour change in Lockout Guard decisions; existing tests keep passing (adapted to the new UI only).
- [x] Key generation still uses the raw-key display outside the alternate screen.
- [x] `teatest`: port change through the Task panel; dangerous delete; disabled lock on own user.

## Comments

Resolved on `feat/ux-redesign` @ b34f963 (merge). Code-review fixes in aa00873.
