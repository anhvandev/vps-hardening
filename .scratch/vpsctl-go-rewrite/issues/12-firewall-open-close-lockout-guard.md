# 12: Firewall — open/remove rules with the Lockout Guard

**What to build:** From the Firewall screen the operator opens a port or range (tcp/udp, optional source IP/CIDR) and removes a rule. Introduces the Lockout Guard as a pure decision module with its first rule: refuse removing the rule that allows the current SSH port, and refuse any change that leaves the SSH port unreachable. Every mutation takes the global lock and writes an action-log line; a second session trying to mutate sees who holds the lock.

**Blocked by:** 09, 11

**Status:** ready-for-agent

- [ ] Input validation: port 1–65535, range start ≤ end, proto tcp|udp, valid IP/CIDR; errors shown inline.
- [ ] Removing a rule touches only that rule; unrelated rules survive (test with 80/tcp, 443/tcp, a source-limited rule).
- [ ] Lockout Guard is a pure function (facts + proposed action → allow | refuse with reason), unit-tested without any command seam; refusal reason shown in the TUI. No override.
- [ ] Lock busy → the action is refused with "locked by <name> (pid N)"; reading still works.
- [ ] Each successful or failed mutation appends one action-log line.
- [ ] `teatest`: open a port, refused SSH-port removal.
