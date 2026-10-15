# 17: Users — create a Managed User and add keys

**What to build:** From the Users screen the operator creates a key-only Managed User (never a password) and adds a key to any Managed User either by pasting a public key or by generating a pair, in which case the private key is shown once via the raw-key display from 15 (or written to a mode-600 file).

**Blocked by:** 09, 15, 16

**Status:** resolved

- [x] Name validation as for the Admin User; existing names and system accounts rejected.
- [x] Pasted keys are validated as public keys before install; duplicates are not added twice.
- [x] authorized_keys ownership/permissions/SELinux context correct (reuse existing key install).
- [x] Global lock + action-log line per mutation; key material never logged.
- [x] Generated key material removed on every path, including failures.

## Comments

Resolved on `feat/vpsctl-tui` @ fd49a0f (merge). Review fixes in b136567.
