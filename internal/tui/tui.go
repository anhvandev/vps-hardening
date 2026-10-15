// Package tui is the management TUI that `sudo vpsctl` opens: a module menu
// on the left, the open screen on the right, and a red banner while the host
// is not hardened.
//
// Adding a screen = one file in this package with a constructor and
//
//	func init() { screens["Firewall"] = newFirewall }
//
// where the title is one of menu. Menu entries without a registered screen
// are shown as "coming soon". A screen is a plain tea.Model, built fresh each
// time it is opened (so it reads the live system then). While open it gets
// every message, including every key except ctrl+c, and returns the Back
// command to hand focus back to the menu.
package tui

import (
	"fmt"
	"slices"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/anhvandev/vpsctl/internal/harden"
)

// menu is the fixed module order; screens fill it in.
var menu = []string{"Overview", "Hardening", "Firewall", "SSH", "Users", "Services", "Timers", "Cron", "fail2ban", "Action log"}

// screens maps a menu title to the constructor of its screen.
var screens = map[string]func(*harden.Machine) tea.Model{}

type backMsg struct{}

// Back is the command a screen returns to give focus back to the menu.
func Back() tea.Msg { return backMsg{} }

// NewVersionMsg tells the shell a newer release exists (its tag); the shell
// shows a notice and never updates on its own.
type NewVersionMsg string

var (
	bannerStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("1")).Padding(0, 1)
	titleStyle  = lipgloss.NewStyle().Bold(true)
	dimStyle    = lipgloss.NewStyle().Faint(true)
	paneStyle   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
	activeColor = lipgloss.Color("6")
)

// Model is the TUI shell. Machine is the real host (or a fake one in tests).
type Model struct {
	m        *harden.Machine
	cursor   int
	screen   tea.Model // open screen, nil if none
	focused  bool      // keys go to screen, not the menu
	hardened bool
	newer    NewVersionMsg // newer release tag, "" if none known
}

// New opens the TUI on the Overview, with the menu focused.
func New(m *harden.Machine) Model {
	return Model{m: m, screen: screens[menu[0]](m), hardened: m.SSH.StageBLive()}
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
	case tea.KeyPressMsg:
		if msg.String() == "ctrl+c" {
			return t, tea.Quit
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

func (t Model) menuKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "q":
		return t, tea.Quit
	case "up", "k":
		t.cursor = max(t.cursor-1, 0)
	case "down", "j":
		t.cursor = min(t.cursor+1, len(menu)-1)
	case "enter":
		return t.open(menu[t.cursor])
	case "h":
		if !t.hardened {
			return t.open("Hardening")
		}
	}
	return t, nil
}

// open builds a fresh screen for title and focuses it; unbuilt titles do nothing.
func (t Model) open(title string) (tea.Model, tea.Cmd) {
	newScreen, ok := screens[title]
	if !ok {
		return t, nil
	}
	t.cursor = slices.Index(menu, title)
	t.screen, t.focused = newScreen(t.m), true
	t.hardened = t.m.SSH.StageBLive()
	return t, t.screen.Init()
}

func (t Model) View() tea.View {
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %s\n", titleStyle.Render("vpsctl"), dimStyle.Render(t.m.Host.DistroID+" "+t.m.Host.Version))
	if !t.hardened {
		hint := "run `sudo vpsctl harden --user NAME`"
		if _, ok := screens["Hardening"]; ok {
			hint = "press h for the Hardening wizard"
		}
		b.WriteString(bannerStyle.Render("NOT HARDENED: SSH still allows password or root login; "+hint) + "\n")
	}

	var items []string
	for i, title := range menu {
		line := "  " + title
		if i == t.cursor {
			line = "> " + title
		}
		switch _, ok := screens[title]; {
		case !ok:
			line = dimStyle.Render(line + " (coming soon)")
		case i == t.cursor:
			line = lipgloss.NewStyle().Bold(true).Foreground(activeColor).Render(line)
		}
		items = append(items, line)
	}
	menuPane, screenPane := paneStyle, paneStyle
	if t.focused {
		screenPane = screenPane.BorderForeground(activeColor)
	} else {
		menuPane = menuPane.BorderForeground(activeColor)
	}
	content := ""
	if t.screen != nil {
		content = t.screen.View().Content
	}
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		menuPane.Render(strings.Join(items, "\n")), screenPane.Render(content)) + "\n")

	help := "↑/↓ move · enter open · q quit"
	if t.focused {
		help = "esc back · ctrl+c quit"
	}
	b.WriteString(dimStyle.Render(help))
	if t.newer != "" {
		b.WriteString("\n" + dimStyle.Render("vpsctl "+string(t.newer)+" available: run `sudo vpsctl self-update`"))
	}

	v := tea.NewView(b.String())
	v.AltScreen = true
	return v
}
