# 03: Shared widgets (expand) with Firewall as the tracer

**What to build:** A shared widget set used by all screens from now on: table (keyboard + mouse row selection, wheel scroll), detail box for the selected row, clickable button row with disabled buttons showing the Lockout Guard reason, form fields, and two-tier confirm dialogs (normal `[Yes] [No]`; dangerous = type the target name). The Firewall screen is rebuilt on them exactly as the design (§4): Listening column, SSH row marked ◆ with `[ Remove ]` disabled and the reason in the detail box.

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] Shared keymap on every widget: `↑↓/jk`, `enter`, `esc`, `/` filter, `r` refresh, `a` add, `d` delete, `e` edit; screen keys listed in the status bar.
- [ ] Mouse hit-testing for rows and buttons (prefer lipgloss v2 native hit-testing if it exists, else bubblezone); `bubbles` components as the base.
- [ ] Lockout Guard refusals are never dialogs: disabled button + reason.
- [ ] `teatest`: click a row, click a button, wheel scroll, dangerous confirm requires the exact name, disabled SSH remove.
