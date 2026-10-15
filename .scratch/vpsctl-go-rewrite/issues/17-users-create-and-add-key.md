# 17: Users — create a Managed User and add keys

**What to build:** From the Users screen the operator creates a key-only Managed User (never a password) and adds a key to any Managed User either by pasting a public key or by generating a pair, in which case the private key is shown once via the raw-key display from 15 (or written to a mode-600 file).

**Blocked by:** 09, 15, 16

**Status:** ready-for-agent

- [ ] Name validation as for the Admin User; existing names and system accounts rejected.
- [ ] Pasted keys are validated as public keys before install; duplicates are not added twice.
- [ ] authorized_keys ownership/permissions/SELinux context correct (reuse existing key install).
- [ ] Global lock + action-log line per mutation; key material never logged.
- [ ] Generated key material removed on every path, including failures.
