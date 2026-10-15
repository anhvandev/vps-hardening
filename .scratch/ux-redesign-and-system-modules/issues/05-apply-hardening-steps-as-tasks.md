# 05: Apply single Hardening Steps and run Hardening as a Task

**What to build:** On Hardening Status each Missing or Skipped step has `[ Apply ]` (and `[ Apply all missing ]`), each running as a Task; SSH port and key rows link to the SSH and Users screens instead. The wizard runs Hardening as a Task whose steps are the Hardening Steps, with the Verify Gate inside the Task panel, and the SUMMARY shown in the result card (no longer only in the log file). After success the screen switches to Hardening Status and the Record is updated.

**Blocked by:** 02, 04

**Status:** ready-for-agent

- [ ] Applying one step changes only that step and updates the Record (a Skipped step that gets applied is no longer Skipped).
- [ ] Stopping at the Verify Gate restores the pre-run SSH state, as today, and shows that in the result card.
- [ ] Private key display still leaves the alternate screen; nothing secret in Task output.
- [ ] `teatest`: apply fail2ban from Status; wizard through the gate with step list and SUMMARY; gate stop path.
