# 09: Move Cron and fail2ban onto Tasks and shared widgets

**What to build:** Cron and fail2ban screens on the shared widgets with every mutation as a Task (add/edit/delete Cron Entry; unban; add to ignoreip with the session IP suggested). fail2ban auto-refreshes every 5 s while visible.

**Blocked by:** 03

**Status:** ready-for-agent

- [ ] Cron Entry commands stay out of Task output and Task History (quiet), as today.
- [ ] Deleting a Cron Entry uses the normal confirm.
- [ ] `teatest`: add a Cron Entry as a Task; unban as a Task; refresh tick.
