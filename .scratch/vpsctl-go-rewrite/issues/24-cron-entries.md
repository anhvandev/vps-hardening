# 24: Cron — view, add, edit, delete Cron Entries

**What to build:** A Cron screen showing Cron Entries of root and each Managed User. The operator adds, edits and deletes entries; an invalid schedule is rejected before the crontab is written.

**Blocked by:** 09, 16

**Status:** ready-for-agent

- [ ] Comments and environment lines in a crontab survive edits untouched.
- [ ] Writes go through the system crontab tool so permissions and daemon notification are correct.
- [ ] Schedule validation covers the five fields and common `@` shortcuts.
- [ ] Global lock + action-log line per mutation.
