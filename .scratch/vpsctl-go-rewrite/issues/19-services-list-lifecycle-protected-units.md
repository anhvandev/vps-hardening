# 19: Services — list, filter, lifecycle actions, Protected Units

**What to build:** A Services screen listing Services (running/enabled/failed by default, toggle for all, name filter) with start, stop, restart, enable and disable. The Lockout Guard gains the Protected Unit rule: ssh/sshd (.service/.socket), ufw, firewalld, networking, resolver and cloud-init cannot be stopped/disabled (ssh cannot be restarted here); fail2ban can be stopped/started.

**Blocked by:** 10, 12

**Status:** ready-for-agent

- [ ] List reads live unit state; filter and toggle tested.
- [ ] Each action shows the resulting state or the systemctl error.
- [ ] Protected Unit refusals unit-tested in the guard and shown with a reason in the TUI.
- [ ] Global lock + action-log line per mutation.
- [ ] `teatest`: restart a Service; refused stop of ssh.
