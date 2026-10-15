package tui

// The frame around every screen: header line with the machine and the
// Hardening badge, grouped sidebar (a tab bar below 100 columns), the open
// screen, and the status bar. Mouse clicks are hit-tested against it here.

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/anhvandev/vpsctl/internal/harden"
)

const (
	sideW         = 24  // sidebar columns
	collapseBelow = 100 // narrower terminals get the tab bar instead
	minW, minH    = 80, 24
)

// ascii is set (in New) when the terminal can't render the status symbols.
var ascii atomic.Bool

var asciiGlyph = map[string]string{"●": "*", "✓": "v", "✗": "x", "⚠": "!", "▶": ">", "◆": "#", "▌": ">", "·": "."}

// glyph is s, or its ASCII stand-in on a terminal that can't render it.
func glyph(s string) string {
	if ascii.Load() {
		return asciiGlyph[s]
	}
	return s
}

// asciiTerm reports a terminal without the symbols: the Linux console, or a
// locale that isn't UTF-8 (unset counts as UTF-8: most SSH clients are).
func asciiTerm() bool {
	if os.Getenv("TERM") == "linux" {
		return true
	}
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := strings.ToLower(os.Getenv(k)); v != "" {
			return !strings.Contains(v, "utf-8") && !strings.Contains(v, "utf8")
		}
	}
	return false
}

func border() lipgloss.Border {
	if ascii.Load() {
		return lipgloss.ASCIIBorder()
	}
	return lipgloss.NormalBorder()
}

// machineLine is "hostname ─ Distro version ─ N vCPU · M GB", read under the
// machine's root; parts that can't be read are left out.
func machineLine(m *harden.Machine) string {
	var parts []string
	if b, _ := os.ReadFile(filepath.Join(m.Root, "/proc/sys/kernel/hostname")); strings.TrimSpace(string(b)) != "" {
		parts = append(parts, strings.TrimSpace(string(b)))
	}
	if d := m.Host.DistroID; d != "" {
		parts = append(parts, strings.ToUpper(d[:1])+d[1:]+" "+m.Host.Version)
	}
	var size []string
	if b, err := os.ReadFile(filepath.Join(m.Root, "/proc/cpuinfo")); err == nil {
		size = append(size, fmt.Sprintf("%d vCPU", strings.Count("\n"+string(b), "\nprocessor")))
	}
	b, _ := os.ReadFile(filepath.Join(m.Root, "/proc/meminfo"))
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "MemTotal:" {
			kb, _ := strconv.ParseFloat(f[1], 64)
			size = append(size, strconv.FormatFloat(math.Round(kb/1024/1024*10)/10, 'f', -1, 64)+" GB")
		}
	}
	if len(size) > 0 {
		parts = append(parts, strings.Join(size, " · "))
	}
	return strings.Join(parts, " "+border().Top+" ")
}

// badge is the Hardening badge at the right of the header.
func (t Model) badge() string {
	if t.hardened {
		return okStyle.Render(glyph("●") + " Hardened")
	}
	return errStyle.Render(glyph("✗") + " NOT HARDENED")
}

// sideRow is one sidebar line: a group heading or a menu item.
type sideRow struct {
	text string
	item bool
}

func sideRows() []sideRow {
	var rows []sideRow
	for _, g := range menu {
		var its []sideRow
		for _, title := range g.titles {
			if _, ok := screens[title]; ok {
				its = append(its, sideRow{title, true})
			}
		}
		if len(its) > 0 {
			rows = append(append(rows, sideRow{g.group, false}), its...)
		}
	}
	return rows
}

// sidebar renders sideRows: the cursor's item is marked, in the accent color
// while the sidebar has focus.
func (t Model) sidebar() []string {
	cur := items()[t.cursor]
	var lines []string
	for _, r := range sideRows() {
		switch {
		case !r.item:
			lines = append(lines, " "+dimStyle.Bold(true).Render(r.text))
		case r.text == cur:
			st := titleStyle
			if !t.focused {
				st = st.Foreground(accent)
			}
			lines = append(lines, " "+st.Render(glyph("▌")+" "+r.text))
		default:
			lines = append(lines, "   "+r.text)
		}
	}
	return lines
}

// tabBar is the narrow terminal's stand-in for the sidebar: the cursor's
// group with its items.
func (t Model) tabBar() string {
	cur := items()[t.cursor]
	for _, g := range menu {
		if !slices.Contains(g.titles, cur) {
			continue
		}
		var its []string
		for _, title := range g.titles {
			switch _, ok := screens[title]; {
			case title == cur:
				its = append(its, lipgloss.NewStyle().Bold(true).Foreground(accent).Render(title))
			case ok:
				its = append(its, title)
			}
		}
		return dimStyle.Bold(true).Render(g.group) + "  " + strings.Join(its, " · ") + "   " + dimStyle.Render("tab menu")
	}
	return ""
}

const helpText = `Keys
  ↑↓ j k   move             enter   open
  esc      back             /       filter
  r        refresh          a d e   add · delete · edit
  tab      to the sidebar (its overlay on a narrow terminal)
  h        Hardening (while not hardened)
  t        reopen the hidden Task
  m        mouse on/off     ?       this help
  ctrl+c   quit             q       quit (from the sidebar)

Mouse: click a sidebar item, the Hardening badge, a hidden Task
in the status bar, table rows and buttons; the wheel scrolls tables.
Shift+drag to select text.

any key closes this help`

// status is the status bar: notices on the left, the keys on the right.
func (t Model) status() (left, right string) {
	if t.busyNote {
		return "busy: a change is running and quits only once it ends (ctrl+c at the Verify Gate = Stop safely)", ""
	}
	switch {
	case t.refused != "":
		left = errStyle.Render(t.refused)
	case t.task != nil && !t.task.shown:
		left = t.taskStatus()
	case t.holder != "" && !t.running():
		left = errStyle.Render("locked by " + t.holder)
	case t.newer != "":
		left = "vpsctl " + string(t.newer) + " available: run `sudo vpsctl self-update`"
	}
	switch {
	case t.task != nil && t.task.shown && t.task.gate != nil:
		right = "←/→ choose · enter confirm · ctrl+c stop safely"
	case t.task != nil && t.task.shown && t.task.ended:
		right = "enter close · o output"
	case t.task != nil && t.task.shown:
		right = "enter hide"
	case t.help:
		right = "any key closes help"
	case t.focused:
		right = "esc back · ctrl+c quit"
		if s, ok := t.screen.(interface{ keys() string }); ok {
			right = s.keys() + " · ? help"
		}
	default:
		right = "↑↓ move · enter open · m mouse · q quit · ? help"
		if !t.hardened {
			right = "h hardening · " + right
		}
	}
	return left, right
}

// fit truncates or pads s to exactly w columns.
func fit(s string, w int) string {
	s = ansi.Truncate(s, w, "")
	return s + strings.Repeat(" ", max(w-ansi.StringWidth(s), 0))
}

func (t Model) View() tea.View {
	v := tea.NewView(t.frame())
	v.AltScreen = true
	if !t.mouseOff {
		v.MouseMode = tea.MouseModeCellMotion
	}
	return v
}

func (t Model) frame() string {
	if t.w < minW || t.h < minH {
		return "terminal too small (need 80×24)"
	}
	bd, inner, wide := border(), t.w-2, t.w >= collapseBelow
	rep := strings.Repeat
	var out []string

	badge := t.badge()
	bw := lipgloss.Width(badge)
	title := ansi.Truncate(" vpsctl "+bd.Top+" "+t.machine+" ", inner-bw-2, "")
	out = append(out, bd.TopLeft+title+rep(bd.Top, inner-ansi.StringWidth(title)-bw-2)+" "+badge+" "+bd.TopRight)

	content := ""
	if t.screen != nil {
		content = t.screen.View().Content
	}
	if t.help {
		content = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1).Render(helpText)
	}
	body := strings.Split(content, "\n")
	if t.task != nil && t.task.shown { // the Task panel, over the screen
		cw, rows := inner-1, t.h-6
		if wide {
			cw, rows = inner-sideW-2, t.h-4
		}
		body = overlay(body, t.panel(min(cw-2, 76), rows-1), 0, 1)
	}
	at := func(ls []string, i int) string {
		if i < len(ls) {
			return ls[i]
		}
		return ""
	}
	side := t.sidebar()
	var sep string
	if wide {
		cw := inner - sideW - 1
		for i := range t.h - 4 {
			out = append(out, bd.Left+fit(at(side, i), sideW)+bd.Left+fit(" "+at(body, i), cw)+bd.Left)
		}
		sep = bd.MiddleLeft + rep(bd.Top, sideW) + bd.MiddleBottom + rep(bd.Top, cw) + bd.MiddleRight
	} else {
		body = append([]string{t.tabBar(), ""}, body...)
		if t.overlay {
			side = append(side, rep(bd.Top, sideW))
		}
		for i := range t.h - 4 {
			line := fit(" "+at(body, i), inner)
			if t.overlay && i < len(side) {
				edge := bd.Left
				if i == len(side)-1 {
					edge = bd.BottomRight
				}
				line = fit(side[i], sideW) + edge + ansi.Cut(line, sideW+1, inner)
			}
			out = append(out, bd.Left+line+bd.Left)
		}
		sep = bd.MiddleLeft + rep(bd.Top, inner) + bd.MiddleRight
	}
	out = append(out, sep)

	left, right := t.status()
	gap := max(inner-2-ansi.StringWidth(left)-ansi.StringWidth(right), 1)
	out = append(out, bd.Left+fit(" "+left+rep(" ", gap)+dimStyle.Render(right), inner)+bd.Left)
	out = append(out, bd.BottomLeft+rep(bd.Top, inner)+bd.BottomRight)
	return strings.Join(out, "\n")
}

// content is where the open screen sits: its top-left cell and size.
func (t Model) content() (x, y, w, h int) {
	if t.w >= collapseBelow {
		return sideW + 3, 1, t.w - sideW - 4, t.h - 4
	}
	return 2, 3, t.w - 3, t.h - 6 // under the tab bar and a blank line
}

// contentSize is the size the open screen gets.
func (t Model) contentSize() tea.WindowSizeMsg {
	_, _, w, h := t.content()
	return tea.WindowSizeMsg{Width: w, Height: h}
}

// local turns terminal cell (x, y) into the open screen's own cell; ok is
// false outside it (or while the narrow sidebar overlays it).
func (t Model) local(x, y int) (int, int, bool) {
	cx, cy, w, h := t.content()
	x, y = x-cx, y-cy
	return x, y, t.w >= minW && t.h >= minH && !t.overlay && x >= 0 && y >= 0 && x < w && y < h
}

// clicked is the menu title a click hits: a sidebar item (when the sidebar
// is shown) or, for the header badge, Hardening. "" when it hits neither.
func (t Model) clicked(msg tea.MouseClickMsg) string {
	if msg.Button != tea.MouseLeft || t.w < minW || t.h < minH {
		return ""
	}
	if msg.Y == 0 && msg.X >= t.w-2-lipgloss.Width(t.badge()) {
		return "Hardening"
	}
	rows, i := sideRows(), msg.Y-1
	if (t.w >= collapseBelow || t.overlay) && msg.X >= 1 && msg.X <= sideW && i >= 0 && i < len(rows) && rows[i].item {
		return rows[i].text
	}
	return ""
}
