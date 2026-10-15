# 23: Timers — list, create, edit

**What to build:** A Timers screen listing Timers with their target Service and next run time. The operator creates a Timer from a form (schedule + target Service) and edits existing ones with the same override/verify-before-apply behaviour as Services.

**Blocked by:** 22

**Status:** resolved

- [x] Schedule validated before saving (systemd calendar syntax); next run shown after creation.
- [x] Editing a packaged Timer uses an override; revert works.
- [x] Global lock + action-log line per mutation.

## Comments

Resolved on `feat/vpsctl-tui` @ a2a05ea (merge). Review fixes in b136567.
