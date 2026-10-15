# 22: Services — create a Service from a form

**What to build:** The operator creates a new Service from a form (name, description, command, user, working directory, restart policy, environment). User defaults to a non-root Managed User; root must be picked explicitly. "Advanced" opens the generated unit in `$EDITOR`. After verification vpsctl offers to enable and start it.

**Blocked by:** 21

**Status:** ready-for-agent

- [ ] Name validated and must not collide with an existing unit.
- [ ] Generated unit verified before it becomes active; failure leaves no unit behind.
- [ ] Enable + start result shown; failure points to the journal view.
- [ ] Global lock + action-log line.
