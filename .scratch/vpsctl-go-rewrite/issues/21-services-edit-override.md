# 21: Services — edit via override, verify, revert

**What to build:** The operator edits any Service through an override (never the vendor file) in `$EDITOR` (nano by default). After saving, vpsctl verifies the unit and reloads systemd; if verification fails nothing is applied and the operator can re-edit or discard. An existing override can be reverted.

**Blocked by:** 19

**Status:** resolved

- [x] The TUI hands the terminal to the editor and resumes cleanly afterwards.
- [x] Invalid edit → no reload, previous override (or none) still in effect; tested with a scripted verify failure.
- [x] Protected Units cannot be edited (guard refusal).
- [x] Revert removes the override and reloads.
- [x] Global lock held for the edit; action-log line with result.

## Comments

Resolved on `feat/vpsctl-tui` @ 60e73f0 (merge). Review fixes in b136567.
