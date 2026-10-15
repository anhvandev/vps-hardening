# 24: Cron — view, add, edit, delete Cron Entries

**What to build:** A Cron screen showing Cron Entries of root and each Managed User. The operator adds, edits and deletes entries; an invalid schedule is rejected before the crontab is written.

**Blocked by:** 09, 16

**Status:** resolved

- [x] Comments and environment lines in a crontab survive edits untouched.
- [x] Writes go through the system crontab tool so permissions and daemon notification are correct.
- [x] Schedule validation covers the five fields and common `@` shortcuts.
- [x] Global lock + action-log line per mutation.

## Comments

Resolved on `feat/vpsctl-tui` @ 862f105 (merge). Review fixes in b136567.
