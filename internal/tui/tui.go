// Package tui is the management TUI that `sudo vpsctl` opens: a frame with
// the machine and its Hardening badge on top, a grouped sidebar on the left,
// the open screen on the right and a status bar with the keys (frame.go).
//
// Adding a screen = one file in this package with a constructor and
//
//	func init() { screens["Firewall"] = newFirewall }
//
// where the title is one of menu. Menu entries without a registered screen
// are hidden. A screen is a plain tea.Model, built fresh each
// time it is opened (so it reads the live system then). While open it gets
// every message, including every key except ctrl+c (unless its busy() says a
// gated job runs), and returns the Back
// command to hand focus back to the menu. Every change to the host goes
// through logMutation (global lock + one action-log line); Lockout Guard checks
// (internal/guard) run inside it, on facts read under the lock.
package tui

import (
	"slices"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/anhvandev/vpsctl/internal/harden"
)

// menu is the sidebar: fixed groups of module titles; screens fill it in.
var menu = []struct {
	group  string
	titles []string
}{
	{"SECURITY", []string{"Hardening", "Firewall", "SSH", "fail2ban", "Logins"}},
	{"ACCESS", []string{"Users"}},
	{"WORKLOADS", []string{"Services", "Timers", "Cron", "Docker"}},
	{"SYSTEM", []string{"Overview", "Updates", "Disk", "Swap", "Action log"}},
}

// items is the menu titles that have a screen, in sidebar order.
func items() []string {
	var ts []string
	for _, g := range menu {
		for _, title := range g.titles {
			if _, ok := screens[title]; ok {
				ts = append(ts, title)
			}
		}
	}
	return ts
}

// screens maps a menu title to the constructor of its screen.
var screens = map[string]func(*harden.Machine) tea.Model{}

type backMsg struct{}

// Back is the command a screen returns to give focus back to the menu.
func Back() tea.Msg { return backMsg{} }

// NewVersionMsg tells the shell a newer release exists (its tag); the shell
// shows a notice and never updates on its own.
type NewVersionMsg string

// Colors: one accent and the status colors, all from the 16 ANSI colors so
// they follow the terminal's own palette (light or dark) and 16-color
// profiles. Yellow (warning, Missing) is warnStyle in ssh.go.
var (
	titleStyle = lipgloss.NewStyle().Bold(true)
	dimStyle   = lipgloss.NewStyle().Faint(true)
	accent     = lipgloss.Color("6")
	okStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("2")) // green: ok
	errStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("1")) // red: error, blocked
	naStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("8")) // grey: n.a.
)

// Model is the TUI shell. Machine is the real host (or a fake one in tests).
type Model struct {
	m        *harden.Machine
	now      time.Time // the clock relative times are measured against
	machine  string    // header: hostname, distro, size
	cursor   int       // index into items()
	screen   tea.Model // open screen, nil if none
	focused  bool      // keys go to screen, not the menu
	hardened bool
	newer    NewVersionMsg // newer release tag, "" if none known
	busyNote bool          // ctrl+c was pressed while a gated job runs
	w, h     int           // terminal size
	mouseOff bool          // m: mouse capture off, the terminal selects text
	help     bool          // ?: keymap overlay shown
	overlay  bool          // tab on a narrow terminal: sidebar shown over the content
}

// New opens the TUI on the Overview, with the menu focused; now is the
// current time.
func New(m *harden.Machine, now time.Time) Model {
	ascii = asciiTerm()
	return Model{m: m, now: now, machine: machineLine(m), cursor: slices.Index(items(), "Overview"),
		screen: screens["Overview"](m), hardened: m.SSH.StageBLive()}
}

func (t Model) Init() tea.Cmd { return t.screen.Init() }

func (t Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case backMsg:
		t.focused = false
		t.hardened = t.m.SSH.StageBLive()
		return t, nil
	case NewVersionMsg:
		t.newer = msg
		return t, nil
	case tea.WindowSizeMsg:
		t.w, t.h = msg.Width, msg.Height
	case tea.MouseClickMsg:
		if title := t.clicked(msg); title != "" && !t.busy() {
			return t.open(title)
		}
	case gateMsg:
		if msg.term != nil { // a job takes the real terminal (raw key display)
			return t, tea.Batch(tea.Exec(msg.term, nil), msg.wait)
		}
		if msg.ask == nil { // a job finished: it may have hardened the host
			t.hardened, t.busyNote = t.m.SSH.StageBLive(), false
		}
	case tea.KeyPressMsg:
		if msg.String() == "ctrl+c" {
			// A running gated job is never abandoned (Stage A would stay
			// without restore): the screen gets ctrl+c instead, which at the
			// Verify Gate means "Stop safely".
			if !t.busy() {
				return t, tea.Quit
			}
			t.busyNote = true
			var cmd tea.Cmd
			t.screen, cmd = t.screen.Update(msg)
			return t, cmd
		}
		if t.help { // any key closes the keymap
			t.help = false
			return t, nil
		}
		if !t.focused {
			return t.menuKey(msg.String())
		}
	}
	if t.screen == nil {
		return t, nil
	}
	var cmd tea.Cmd
	t.screen, cmd = t.screen.Update(msg)
	return t, cmd
}

// busy reports whether the open screen runs a gated job.
func (t Model) busy() bool {
	b, ok := t.screen.(interface{ busy() bool })
	return ok && b.busy()
}

func (t Model) menuKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "q":
		return t, tea.Quit
	case "up", "k":
		t.cursor = max(t.cursor-1, 0)
	case "down", "j":
		t.cursor = min(t.cursor+1, len(items())-1)
	case "enter":
		return t.open(items()[t.cursor])
	case "h":
		if !t.hardened {
			return t.open("Hardening")
		}
	case "?":
		t.help = true
	case "m":
		t.mouseOff = !t.mouseOff
	case "tab":
		t.overlay = !t.overlay
	case "esc":
		t.overlay = false
	}
	return t, nil
}

// open builds a fresh screen for title and focuses it; unbuilt titles do nothing.
func (t Model) open(title string) (tea.Model, tea.Cmd) {
	newScreen, ok := screens[title]
	if !ok {
		return t, nil
	}
	t.cursor = slices.Index(items(), title)
	t.screen, t.focused, t.overlay, t.help = newScreen(t.m), true, false, false
	t.hardened = t.m.SSH.StageBLive()
	return t, t.screen.Init()
}
