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
// every message, including every key except ctrl+c, and returns the Back
// command to hand focus back to the menu. Its tea.WindowSizeMsg and mouse
// messages are in its own cells; screens are built on the shared widgets
// (widgets.go, which also lists the optional keys/typing methods the shell
// asks). Every change to the host goes
// through a Task (task.go: global lock + one Task History line); Lockout
// Guard checks (internal/guard) run inside it, on facts read under the lock.
package tui

import (
	"path/filepath"
	"slices"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/anhvandev/vpsctl/internal/actionlog"
	"github.com/anhvandev/vpsctl/internal/docker"
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
	{"SYSTEM", []string{"Overview", "Updates", "Disk", "Swap", "Task History"}},
}

// items is the menu titles that have a screen, in sidebar order.
func items() []string {
	var ts []string
	for _, g := range menu {
		for _, title := range g.titles {
			if shown(title) {
				ts = append(ts, title)
			}
		}
	}
	return ts
}

// shown reports whether title is in the menu: it has a screen, and Docker
// is installed for the Docker one.
func shown(title string) bool {
	_, ok := screens[title]
	return ok && !(title == "Docker" && noDocker.Load())
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

	selectedStyle = lipgloss.NewStyle().Reverse(true)
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
	busyNote bool          // ctrl+c or q was pressed while a Task runs
	w, h     int           // terminal size
	mouseOff bool          // m: mouse capture off, the terminal selects text
	help     bool          // ?: keymap overlay shown
	overlay  bool          // tab on a narrow terminal: sidebar shown over the content
	task     *task         // the running Task, or the ended one until its card is closed
	refused  string        // why the last Task did not start; cleared once the lock is free
	holder   string        // who holds the global lock, "" if free (read every tick)
	refresh  time.Time     // when the open screen last got a refreshMsg (or opened)

	// Hardening badge (readHardening): hardened is SSH key-only; done of
	// chosen counts the Hardening Steps Done of those not Skipped.
	done, chosen int
}

// tickMsg is the shell's clock: every second it moves now and re-reads the
// lock holder.
type tickMsg struct {
	now    time.Time
	holder string
}

// refreshEvery is how often the open screen gets a refreshMsg.
const refreshEvery = 5 * time.Second

// refreshMsg tells the open screen to re-read the host (auto-refresh: screens
// that refresh while visible reload on it, others ignore it). The shell sends
// it every refreshEvery from its clock; tests send it directly.
type refreshMsg struct{}

func (t Model) tick() tea.Cmd {
	return tea.Tick(time.Second, func(now time.Time) tea.Msg {
		return tickMsg{now, actionlog.Holder(filepath.Join(t.m.Root, actionlog.LockPath))}
	})
}

// New opens the TUI on the Overview, with the menu focused; now is the
// current time.
func New(m *harden.Machine, now time.Time) Model {
	ascii.Store(asciiTerm())
	noDocker.Store(!docker.Installed(m.R))
	t := Model{m: m, now: now, machine: machineLine(m), cursor: slices.Index(items(), "Overview"),
		screen: screens["Overview"](m), refresh: now}
	t.readHardening()
	return t
}

func (t Model) Init() tea.Cmd { return tea.Batch(t.screen.Init(), t.tick()) }

func (t Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tickMsg:
		t.now, t.holder = msg.now, msg.holder
		if msg.holder == "" {
			t.refused = ""
		}
		var cmd tea.Cmd // the open screen sees the clock too (Overview's "refreshed Ns ago")
		t.screen, cmd = t.screen.Update(msg)
		if msg.now.Sub(t.refresh) < refreshEvery {
			return t, tea.Batch(t.tick(), cmd)
		}
		t.refresh = msg.now
		var rcmd tea.Cmd
		t.screen, rcmd = t.screen.Update(refreshMsg{})
		cmd = tea.Batch(cmd, rcmd)
		return t, tea.Batch(t.tick(), cmd)
	case startTaskMsg:
		return t.startTask(msg)
	case taskStepMsg, taskWarnMsg, taskLineMsg, taskEndMsg, taskGateMsg, taskTermMsg:
		return t.taskUpdate(msg)
	case backMsg:
		t.focused = false
		t.readHardening()
		return t, nil
	case NewVersionMsg:
		t.newer = msg
		return t, nil
	case openMsg: // a screen links to an item on another screen
		m, cmd := t.open(msg.title)
		t = m.(Model)
		t.screen, _ = t.screen.Update(msg)
		return t, cmd
	case tea.WindowSizeMsg:
		t.w, t.h = msg.Width, msg.Height
		var cmd tea.Cmd
		t.screen, cmd = t.screen.Update(t.contentSize())
		return t, cmd
	case tea.MouseClickMsg:
		if t.task != nil && t.task.shown { // the panel is modal
			return t.panelClick(msg), nil
		}
		if t.task != nil && msg.Button == tea.MouseLeft && msg.Y == t.h-2 { // the status bar reopens it
			t.task.shown = true
			return t, nil
		}
		if title := t.clicked(msg); title != "" {
			return t.open(title)
		}
		x, y, ok := t.local(msg.X, msg.Y)
		if !ok || t.help {
			return t, nil
		}
		t.focused = true // a click into the screen gives it the keys
		msg.X, msg.Y = x, y
		var cmd tea.Cmd
		t.screen, cmd = t.screen.Update(msg)
		return t, cmd
	case tea.MouseWheelMsg:
		x, y, ok := t.local(msg.X, msg.Y)
		if !ok || t.help || t.task != nil && t.task.shown {
			return t, nil
		}
		msg.X, msg.Y = x, y
		var cmd tea.Cmd
		t.screen, cmd = t.screen.Update(msg)
		return t, cmd
	case tea.KeyPressMsg:
		if msg.String() == "ctrl+c" {
			// A running Task is never abandoned (Stage A would stay without
			// restore); at the Verify Gate ctrl+c means "Stop safely".
			if !t.running() {
				return t, tea.Quit
			}
			t.busyNote = true
			if t.task.gate != nil {
				return t.panelKey("ctrl+c")
			}
			return t, nil
		}
		if t.task != nil && t.task.shown {
			return t.panelKey(msg.String())
		}
		if t.help { // any key closes the keymap
			t.help = false
			return t, nil
		}
		if !t.focused {
			return t.menuKey(msg.String())
		}
		if s, ok := t.screen.(interface{ typing() bool }); ok && !s.typing() {
			switch msg.String() { // screens on the shared widgets leave these to the shell
			case "?":
				t.help = true
				return t, nil
			case "m":
				t.mouseOff = !t.mouseOff
				return t, nil
			case "tab": // to the sidebar
				t.focused, t.overlay = false, t.w < collapseBelow
				return t, nil
			}
		}
	}
	if t.screen == nil {
		return t, nil
	}
	var cmd tea.Cmd
	t.screen, cmd = t.screen.Update(msg)
	return t, cmd
}

func (t Model) menuKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "q":
		if t.running() {
			t.busyNote = true
			return t, nil
		}
		return t, tea.Quit
	case "t":
		if t.task != nil {
			t.task.shown = true
		}
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
	if !shown(title) {
		return t, nil
	}
	if c, ok := t.screen.(interface{ close() }); ok { // e.g. stop following logs
		c.close()
	}
	t.cursor = slices.Index(items(), title)
	t.screen, t.focused, t.overlay, t.help, t.refresh = screens[title](t.m), true, false, false, t.now
	t.readHardening()
	t.screen, _ = t.screen.Update(t.contentSize())
	return t, t.screen.Init()
}
