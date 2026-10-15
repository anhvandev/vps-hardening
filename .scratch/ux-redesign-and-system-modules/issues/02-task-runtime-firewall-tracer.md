# 02: Task runtime (expand) with Firewall as the tracer

**What to build:** Every mutation can run as a Task: a panel over the current screen with the Task name, its steps (done / running / pending), live output and, at the end, a result card (green Done with summary, or red Failed with the failing step and reason) that stays until closed. `[ Hide ]` keeps the Task running and shows it in the status bar (click to reopen). The status bar also shows "locked by <name> (pid N)" when another session holds the global lock. Quitting is blocked while a Task runs; mutating Tasks cannot be cancelled. Each Task writes one Task History entry plus its full output to its own file. Opening and removing a Firewall Rule are the first screens moved onto Tasks; the old mutation path stays for every other screen.

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] Only one mutating Task at a time (global lock); a second attempt is refused with the holder shown.
- [ ] A Task's output file never contains private keys or values marked quiet (Cron commands etc.), same rule as today's log.
- [ ] Navigating to another screen while a Task runs keeps it running; its result is still delivered.
- [ ] `teatest`: open a port as a Task (steps, output, Done card), forced failure (Failed card names the step), Hide then reopen from the status bar, quit blocked while running.
