# 18: Users — sudo, lock, key removal, delete, with Lockout Guard

**What to build:** The operator grants/revokes passwordless sudo, locks/unlocks, removes a single key, and deletes a Managed User (keep home by default, optional removal). The Lockout Guard gains two rules: refuse any of these on the current session's user, and refuse any change that would leave zero usable Admin Users (sudo + key + unlocked).

**Blocked by:** 12, 17

**Status:** ready-for-agent

- [ ] Sudo grant validated with visudo and installed atomically; revoke removes only vpsctl's rule.
- [ ] Guard scenarios unit-tested: alice locks bob (allowed), alice locks alice (refused), last usable Admin User revoked (refused), same behaviour on console sessions.
- [ ] Delete asks about the home directory with "keep" as the default.
- [ ] Global lock + action-log line per mutation.
