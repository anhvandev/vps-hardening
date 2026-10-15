# UX redesign and system modules

Status: ready-for-agent

Mockups: `design.md` (approved). Tickets: `issues/01–17`. Vocabulary: `GLOSSARY.md`. Builds on the vpsctl TUI (`../vpsctl-go-rewrite/spec.md`, ADR-0001).

## Problem Statement

The vpsctl TUI works but is hard to read while it works. When the operator triggers something long (installing fail2ban, Hardening, an SSH port change) the screen just says `loading…` or `hardening…`; there is no sign of which step is running, and afterwards only a small status line says whether it worked. The Hardening steps and SUMMARY go only to a log file. Re-opening Hardening shows an empty form: the operator can't tell whether Hardening already ran, with which user and port, which parts are in effect, or which were skipped — and can run it again blindly. Every screen hand-rolls its own list, form and y/n prompt, so behaviour and look differ from screen to screen, and nothing responds to the mouse.

The operator also still drops to the shell for routine VPS chores vpsctl doesn't cover: seeing who logged in or tried to, installing pending updates and rebooting, adding swap on a small VPS, finding what fills the disk and cleaning it up, and managing Docker containers — including the common trap where Docker Published Ports bypass the firewall entirely.

## Solution

A redesigned TUI with a grouped sidebar, a header showing the machine and its Hardening badge, a status bar, consistent widgets, two-tier confirmations and mouse support. Every mutating operation runs as a **Task**: a panel with its steps, live output and a clear Done/Failed result, which can be hidden while it keeps running in the status bar, and which is kept in **Task History** with its full output. Hardening becomes a **Hardening Status** checklist read live from the machine, with a small **Hardening Record** remembering what the machine can't tell (when, which Admin User, which steps were skipped); each missing step can be applied on its own, and the full wizard appears only on an unhardened machine. New screens: Logins, Updates (with reboot), Swap, Disk (with cleanup) and Docker (with Published Port warnings on the Firewall screen).

## User Stories

### Frame, navigation, look
1. As an operator, I want modules grouped in a sidebar (Security, Access, Workloads, System), so that I find things without scanning a long list.
2. As an operator, I want a header with hostname, distro, machine size and a Hardening badge, so that I always know which machine I'm on and whether it's safe.
3. As an operator, I want to click the Hardening badge to open Hardening, so that problems are one click away.
4. As an operator, I want a status bar that always shows the running Task or who holds the lock, so that I never wonder whether something is happening.
5. As an operator, I want the screen's keys always listed in the status bar, so that I don't have to memorise them.
6. As an operator, I want `?` to show the full keymap, so that I can learn the tool.
7. As an operator, I want the same keys on every screen (move, open, back, filter, refresh, add, delete, edit, quit), so that what I learn once works everywhere.
8. As an operator on a narrow terminal, I want the sidebar to collapse into a tab bar, so that content stays readable.
9. As an operator on a tiny terminal, I want a clear "terminal too small" message, so that I don't see a broken layout.
10. As an operator, I want colors that work on light and dark terminals and on 16-color terminals, so that the UI is readable anywhere I SSH from.
11. As an operator on a limited terminal, I want ASCII fallbacks for status symbols, so that nothing renders as garbage.
12. As an operator, I want consistent status colors (green ok, yellow warning/Missing, red error/blocked, grey n.a.), so that I read state at a glance.

### Mouse
13. As an operator, I want to click sidebar items, table rows, buttons, tabs and Overview cards, so that I can drive the tool with the mouse.
14. As an operator, I want the mouse wheel to scroll tables and logs, so that long lists are easy to browse.
15. As an operator, I want to toggle mouse capture with `m`, so that I can select and copy text when I need to.
16. As an operator, I want the help to tell me Shift+drag selects text, so that I can copy without turning the mouse off.

### Tasks
17. As an operator, I want every change to run as a Task with a name and a list of steps, so that I can see what it is doing.
18. As an operator, I want live output from the underlying commands in the Task panel, so that I can watch long installs progress.
19. As an operator, I want a clear Done card with a summary or a Failed card naming the failing step and reason, so that I know the outcome without reading logs.
20. As an operator, I want the result card to stay until I close it, so that I don't miss it.
21. As an operator, I want to hide a running Task and keep working, with its progress in the status bar, so that a long install doesn't block me from reading other screens.
22. As an operator, I want to reopen a hidden Task by clicking the status bar, so that I can check on it.
23. As an operator, I want only one changing Task at a time across all sessions, with the lock holder shown, so that two admins never collide.
24. As an operator, I want mutating Tasks to be impossible to cancel mid-way, so that the machine is never left half-changed.
25. As an operator, I want long read-only scans (like the disk scan) to be cancellable, so that I'm not stuck waiting.
26. As an operator, I want quitting blocked while a Task runs, so that I can't abandon a change.
27. As an operator, I want every Task recorded in Task History with its full output, so that I can audit what happened later.
28. As an operator, I want secrets (private keys, Cron Entry commands) kept out of Task output and history, so that logs never leak them.

### Task History
29. As an operator, I want Task History listed newest first with time, operator, Task and result, so that I see recent changes.
30. As an operator, I want to filter Task History by text, so that I find a specific change.
31. As an operator, I want to open the full output of any past Task, so that I can see exactly what it did.
32. As an operator, I want entries recorded before this change to still appear, so that history isn't lost.

### Confirmations and guard feedback
33. As an operator, I want routine actions (restart a Service, remove a Firewall Rule, delete a Cron Entry) confirmed with Yes/No, so that a misclick doesn't act.
34. As an operator, I want dangerous actions (reboot, delete user, remove swap, remove old kernels, install all updates) to require typing the target name, so that I only do them deliberately.
35. As an operator, I want actions the Lockout Guard refuses shown as disabled buttons with the reason, so that I understand why instead of meeting an error.
36. As an operator, I want items the Lockout Guard protects marked ◆, so that I know before I try.

### Hardening Status
37. As an operator, I want the Hardening screen on a hardened machine to show each Hardening Step as Done, Missing or Skipped, so that I know exactly what is in effect.
38. As an operator, I want to see when Hardening ran and which Admin User it created, so that I know its history.
39. As an operator, I want steps I deliberately skipped shown as Skipped, not Missing, so that I can tell choice from drift.
40. As an operator, I want a step that was applied but is no longer in effect shown as Missing with "was applied <date>", so that I notice drift.
41. As an operator, I want to apply a single Missing or Skipped step, so that I don't re-run all of Hardening.
42. As an operator, I want "Apply all missing", so that I can restore the full set in one go.
43. As an operator, I want SSH port and key rows to send me to the SSH and Users screens, so that those changes always use their safe flows.
44. As an operator, I want the wizard only on an unhardened machine, so that I can't blindly re-run Hardening.
45. As an operator, I want the wizard to run as a Task with Hardening Steps as its steps, the Verify Gate inside the panel and the SUMMARY in the result card, so that I see Hardening happen.
46. As an operator, I want stopping at the Verify Gate to restore the previous SSH state and say so, so that stopping is safe and clear.
47. As an operator, I want the Hardening badge to show x/y, red when SSH isn't key-only and yellow when other steps are Missing, so that severity is obvious.
48. As an operator who hardens with the CLI, I want the same Hardening Record saved, so that the TUI knows about CLI runs.

### Overview
49. As an operator, I want Overview as four cards (Security, Resources, Updates, Services), so that I get machine health in one look.
50. As an operator, I want each card and each warning clickable to the exact screen or item, so that I can act on what I see.
51. As an operator, I want Overview to refresh every 5 seconds with "refreshed Ns ago", so that it's live.
52. As an operator, I want missing components shown as a state, not an error, so that a machine without fail2ban or Docker still renders cleanly.

### Logins
53. As an operator, I want to see successful SSH logins with user, source IP and time, so that I know who got in.
54. As an operator, I want to see failed login attempts and the top failing IPs, so that I gauge attack pressure.
55. As an operator, I want to switch between 24 hours and 7 days, so that I see trends.
56. As an operator, I want my own session marked, so that I recognise it.
57. As an operator, I want a Logins line on Overview, so that I notice unusual activity.

### Updates and reboot
58. As an operator, I want to list pending updates with current and new versions and whether they're security fixes, so that I know what's waiting.
59. As an operator, I want to install security updates now as a Task, so that I patch without waiting for the automatic run.
60. As an operator, I want to install all updates with a dangerous confirm, so that bigger upgrades are deliberate.
61. As an operator, I want to see reboot-required and reboot after typing `reboot`, so that kernel updates take effect safely.
62. As an operator, I want reboot refused while another session holds the lock, so that I don't reboot under someone's running change.
63. As an operator, I want the reboot recorded in Task History before the machine goes down, so that the record is complete.

### Swap
64. As an operator, I want to see current swap and RAM, so that I know whether I'm exposed to OOM.
65. As an operator, I want to create a swapfile with a suggested size, so that small VPSes stop crashing.
66. As an operator, I want to resize or remove vpsctl's swapfile, so that I can adjust it later.
67. As an operator, I want the swapfile to persist across reboots, so that I set it once.
68. As an operator, I want existing swap partitions shown but not modifiable, so that the tool never touches what it didn't create.
69. As an operator, I want removing or shrinking swap refused when it would risk OOM, so that I don't crash the machine.
70. As an operator, I want creation refused when the disk lacks space, so that nothing is half-written.
71. As an operator, I want a "Create swap" shortcut on Overview when there is none, so that I fix it in one click.

### Disk
72. As an operator, I want usage bars per filesystem, so that I see what's filling up.
73. As an operator, I want the largest directories under a mount, so that I find what uses the space.
74. As an operator, I want to cancel a slow scan, so that I'm not stuck.
75. As an operator, I want each cleanup to show reclaimable space before running, so that I know whether it's worth it.
76. As an operator, I want to vacuum the journal, clean the package cache and remove old kernels, so that I reclaim space safely.
77. As an operator, I want the running kernel and one previous kernel always kept, so that a cleanup never makes the machine unbootable.
78. As an operator, I want no arbitrary file deletion on this screen, so that I can't destroy data by accident.

### Docker
79. As an operator with Docker, I want containers listed with project, state, ports and image, so that I see what runs.
80. As an operator, I want containers grouped by compose project, so that I see related services together.
81. As an operator, I want Published Ports on all interfaces flagged, with how to fix them, so that I'm not silently exposed.
82. As an operator, I want the Firewall screen to show Published Ports as bypassing the firewall, so that the firewall view tells the truth.
83. As an operator, I want to start, stop and restart a container as a Task, so that I manage containers without the docker CLI.
84. As an operator, I want to follow a container's logs, so that I can debug it.
85. As an operator, I want to prune dangling Docker images from the Disk screen, so that I reclaim space safely.
86. As an operator without Docker, I want the Docker module hidden, so that the menu stays clean.

## Implementation Decisions

- **Seams**: no new seam. Host access stays on the existing command `Runner` (scripted fake in tests) plus the configurable root directory for real file I/O (temp dir in tests). New features (docker, journal-based logins, apt/dnf updates, swap, df/du, reboot, Hardening Record, Task output files) all go through these. The TUI model receives "now" at construction so relative times are deterministic; auto-refresh is driven by tick messages, injectable in tests.
- **Task runtime** (shell level): a Task has a name, an ordered step list (pending / running / done / failed), streamed output lines and a result (Done + summary | Failed + step + reason). One mutating Task at a time via the existing global lock; the lock holder is surfaced in the status bar. Tasks survive screen navigation; quit is blocked while one runs; mutating Tasks are not cancellable, read-only long scans are. Each Task appends one Task History entry and writes its full output to its own file; the existing quiet-error rule keeps secrets out of both. Introduced alongside the current mutation helper and migrated screen by screen (expand–contract), first on Firewall.
- **Shared widgets** on `bubbles` (table, text input, viewport, spinner, help): table with keyboard + mouse selection and wheel scroll, detail box, clickable button row with disabled-with-reason buttons, form fields, two-tier confirm dialogs. Mouse hit-testing via lipgloss v2 native support if available, otherwise `bubblezone`. Lockout Guard refusals render as disabled buttons + reason, never as dialogs.
- **Frame**: grouped sidebar (Security: Hardening, Firewall, SSH, fail2ban, Logins · Access: Users · Workloads: Services, Timers, Cron, Docker · System: Overview, Updates, Disk, Swap, Task History); header with hostname, distro, size and Hardening badge; status bar with running Task / lock holder and screen keys; `?` keymap overlay; `m` mouse toggle (mouse on by default); collapse below 100 columns; minimum 80×24; one adaptive accent color, fixed status colors, 16-color readable, ASCII fallbacks, no emoji. Overview is the default screen.
- **Shared keymap**: `↑↓/jk` move · `enter` open · `esc` back · `/` filter · `r` refresh · `a` add · `d` delete · `e` edit · `?` help · `q` quit.
- **Auto-refresh** every 5 s while visible: Overview, Docker, fail2ban, Logins, Services. Others refresh on `r` and after each Task.
- **Hardening Status**: one live check per Hardening Step (Admin User + key, key-only SSH + no root login, SSH port, firewall on, Default Cloud Users locked, cloud-init re-injection block, fail2ban, automatic security updates, sysctl). State = Done | Missing | Skipped, with "was applied <date>" when the Record says a Missing step was applied. Without a Record, only Done/Missing are possible.
- **Hardening Record**: written atomically by every Hardening run (CLI and TUI) and by per-step Apply; holds run time, Admin User, skipped steps and per-step applied dates. No secrets. Only data the machine can't tell, consistent with "live system is the source of truth".
- **Hardening flow**: wizard only when SSH is not key-only; otherwise the screen is Hardening Status with per-step Apply and Apply all missing (each a Task). Port and key rows link to SSH and Users. Wizard runs as a Task whose steps are the Hardening Steps, Verify Gate in the panel, SUMMARY in the result card.
- **Badge/banners**: `Hardening x/y`; red when SSH isn't key-only, yellow when other steps are Missing, green otherwise.
- **Logins**: read-only, from the system journal/auth sources on both families; 24 h default, 7 d toggle; top failing IPs; own session marked; no ban action.
- **Updates**: list pending with kind (security/other) after refreshing package lists; install security (normal confirm) or all (dangerous) as Tasks; reboot requires typing `reboot`, refused while another session holds the lock, logged before going down. No scheduled reboot.
- **Swap**: vpsctl manages exactly one swapfile of its own (suggested size = RAM, max 4 GB), persisted across reboots; create/resize/remove; partitions read-only; refuse remove/shrink when swap in use exceeds free RAM; refuse create without disk space. swappiness not managed.
- **Disk**: per-filesystem usage; bounded-depth largest-directory scan skipping pseudo filesystems, cancellable; cleanups with reclaimable size shown first: journal vacuum to N MB, package cache clean, old kernels (keep running + one previous; dangerous confirm), dangling Docker images (when Docker exists). No arbitrary deletion.
- **Docker**: module hidden without Docker; containers grouped by compose project (display only); Published Ports on all interfaces flagged with fix guidance and shown on the Firewall screen as bypassing it; start/stop/restart, logs with follow. vpsctl never edits Docker's firewall rules, never pulls/creates containers or edits compose files.
- **Overview cards**: Security (Hardening x/y, SSH, Firewall, Docker, Logins 24h), Resources (CPU, RAM, Swap, Disk, uptime), Updates (pending counts, last auto-run, reboot required), Services (running, failed by name, Timers that missed their last run). Cards and warnings are clickable.
- **Naming**: "Action log" becomes "Task History" in the UI and the vocabulary.

## Testing Decisions

- **Good tests check external behaviour only**: drive a module's public operations or the TUI model with the fake `Runner` and a temp root, then assert on what an operator or the machine would observe — rendered screen, Task steps and result, Task History entry, resulting files, commands issued and their order. No assertions on private helpers or internal state.
- **Unit-tested modules**: Hardening Step detection (every Done/Missing/Skipped/"was applied" combination, with and without a Record), Hardening Record persistence, Task runtime (one-at-a-time, lock holder, output file, quiet secrets, Task History entry), Logins parsing for both distro families, Updates listing/security selection on apt and dnf, Swap safety rules (OOM refusal, disk space, fstab persistence), Disk cleanup reclaimable sizes and kernel keep-rule, Docker parsing and Published Port detection. Lockout Guard stays a pure-function test.
- **TUI via `teatest`** with the fake `Runner` underneath: wide/narrow/too-small frame, sidebar and row/button clicks, wheel scroll, `m` toggle, `?` overlay, Task panel (running, Done, Failed, Hide and reopen, quit blocked), confirm tiers, disabled guarded buttons, refresh ticks injected (no real waiting), Hardening Status renders and per-step Apply, wizard through the Verify Gate.
- **Prior art**: the existing `teatest` suites for every current screen, the fake-`Runner` unit tests in each internal package, and the container matrix running the real binary on the six supported distros.
- **Container matrix**: each ticket extends it where the environment permits (e.g. Hardening Record after `vpsctl harden`, Updates listing); Swap only where containers allow enabling swap.
- **Expand–contract**: during migration both the old mutation path and Tasks coexist; the full suite stays green after every migration ticket; the contract ticket proves no screen mutates outside a Task.

## Out of Scope

- WireGuard (deferred; questions Q8–Q13 of the grilling session stay open).
- Banning IPs from the Logins screen; fail2ban manual bans.
- Scheduled reboots; automatic reboots.
- swappiness or any sysctl tuning UI.
- Arbitrary file or directory deletion from the Disk screen.
- Docker image pulls, container creation, compose file editing, volume/network management, editing Docker's firewall rules.
- Cancelling mutating Tasks.
- Re-running the full Hardening wizard on a hardened machine.
- Emoji in the UI; localization.

## Further Notes

- Delivery order and blocking edges are in `issues/`: 01 frame → 02 Task runtime → 03 shared widgets; after 03 the Hardening Status, screen migrations and new modules proceed in parallel; 17 removes the old mutation path last.
- Seams were proposed (no new seam; existing `Runner` + root, `teatest` above) and accepted before ticketing.
- Mockups in `design.md` are the visual contract; deviations should be raised, not silently made.
