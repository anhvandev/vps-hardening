# 18: Users — sudo, lock, key removal, delete, with Lockout Guard

**What to build:** The operator grants/revokes passwordless sudo, locks/unlocks, removes a single key, and deletes a Managed User (keep home by default, optional removal). The Lockout Guard gains two rules: refuse any of these on the current session's user, and refuse any change that would leave zero usable Admin Users (sudo + key + unlocked).

**Blocked by:** 12, 17

**Status:** resolved

- [x] Sudo grant validated with visudo and installed atomically; revoke removes only vpsctl's rule.
- [x] Guard scenarios unit-tested: alice locks bob (allowed), alice locks alice (refused), last usable Admin User revoked (refused), same behaviour on console sessions.
- [x] Delete asks about the home directory with "keep" as the default.
- [x] Global lock + action-log line per mutation.

## Comments

Resolved on `feat/vpsctl-tui` @ dd1441d (merge). Review fixes in b136567.
