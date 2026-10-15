# 15: Hardening wizard in the TUI

**What to build:** The banner shortcut and a menu entry open a Hardening wizard collecting the same inputs as `vpsctl harden` (admin user, optional port, key to screen or file, skip options), then runs the existing Hardening flow with the Verify Gate dialog from 14. When a private key is generated the TUI leaves the alternate screen, prints the raw key with no borders, waits for the operator to type `saved`, then returns; or writes it to a mode-600 file if chosen.

**Blocked by:** 14

**Status:** resolved

- [x] Same validation as the CLI (reject root, Default Cloud User names, system accounts; `--port` with skip-firewall rejected).
- [x] Private key never appears in the TUI frame, the Hardening log or the action log.
- [x] The raw-key display is a reusable piece (used again by 17).
- [x] Stopping at the gate behaves like CLI exit 3: pre-run SSH restored, banner stays.
- [x] After success the banner disappears without restarting the TUI.
- [x] `teatest`: wizard happy path with scripted host; gate stop path.

## Comments

Resolved on `feat/vpsctl-tui` @ 77edc5d (merge). Review fixes in b136567.
