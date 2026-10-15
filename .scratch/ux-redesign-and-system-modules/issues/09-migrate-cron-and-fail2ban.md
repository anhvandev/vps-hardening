# 09: Move Cron and fail2ban onto Tasks and shared widgets

**What to build:** Cron and fail2ban screens on the shared widgets with every mutation as a Task (add/edit/delete Cron Entry; unban; add to ignoreip with the session IP suggested). fail2ban auto-refreshes every 5 s while visible.

**Blocked by:** 03

**Status:** resolved

- [x] Cron Entry commands stay out of Task output and Task History (quiet), as today.
- [x] Deleting a Cron Entry uses the normal confirm.
- [x] `teatest`: add a Cron Entry as a Task; unban as a Task; refresh tick.

## Comments

Resolved on `feat/ux-redesign` @ 3a83ef2 (merge). Code-review fixes in aa00873.
