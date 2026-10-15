# 01: New frame — grouped sidebar, header, status bar, mouse on sidebar, help

**What to build:** `sudo vpsctl` opens the new frame from the design (§0): a sidebar grouped SECURITY / ACCESS / WORKLOADS / SYSTEM, a header with hostname, distro, size and a Hardening badge (red NOT HARDENED / green, from the current SSH check until 04 adds x/y), and a bottom status bar with screen keys. Existing screens render unchanged inside the content area. Clicking a sidebar item opens it; `m` toggles mouse capture; `?` opens a full keymap overlay that notes "Shift+drag to select text". Menu items for modules not built yet are hidden.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] Width < 100 collapses the sidebar to a one-line tab bar; `tab` opens it as an overlay; below 80×24 only "terminal too small (need 80×24)" is shown.
- [ ] One adaptive accent color; status colors green/yellow/red/grey; readable on a 16-color profile; ASCII fallbacks for `● ✓ ✗ ⚠ ▶ ◆` when the terminal can't render them.
- [ ] Overview stays the default screen; keyboard navigation of the sidebar still works.
- [ ] `teatest`: wide and narrow layouts, too-small message, sidebar click opens a screen, `m` toggles mouse, `?` overlay.
- [ ] The TUI model takes "now" at construction so relative times are deterministic in tests.
