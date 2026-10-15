package tui

import (
	"fmt"
	"strings"
	"text/tabwriter"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/service"
)

func init() { screens["Timers"] = newTimers }

// timersScreen lists Timers read live, with their next run and target Service.
type timersScreen struct {
	m      *harden.Machine
	loaded bool
	list   []service.Timer
	err    error // list unreadable
	cursor int
	status string
}

// timersMsg is one read of the Timers, plus the outcome of the last action.
type timersMsg struct {
	list   []service.Timer
	err    error
	status string
}

func newTimers(m *harden.Machine) tea.Model { return timersScreen{m: m} }

func (s timersScreen) Init() tea.Cmd { return s.reload("") }

func (s timersScreen) reload(status string) tea.Cmd {
	return func() tea.Msg {
		list, err := service.ListTimers(s.m.R)
		return timersMsg{list, err, status}
	}
}

func (s timersScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case timersMsg:
		s.list, s.err, s.status, s.loaded = msg.list, msg.err, msg.status, true
		s.cursor = max(min(s.cursor, len(s.list)-1), 0)
	case tea.KeyPressMsg:
		switch msg.String() {
		case "esc":
			return s, Back
		case "up", "k":
			s.cursor = max(s.cursor-1, 0)
		case "down", "j":
			s.cursor = max(min(s.cursor+1, len(s.list)-1), 0)
		}
	}
	return s, nil
}

func (s timersScreen) View() tea.View {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Timers") + "\n\n")
	switch {
	case !s.loaded:
		return tea.NewView(b.String() + "loading…")
	case s.err != nil:
		b.WriteString("Timers unreadable: " + s.err.Error())
	case len(s.list) == 0:
		b.WriteString("no Timers")
	default:
		var table strings.Builder
		tw := tabwriter.NewWriter(&table, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "Timer\tNext run\tService")
		for _, t := range s.list {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", t.Name, or(t.Next, "-"), or(t.Service, "-"))
		}
		tw.Flush()
		lines := strings.Split(table.String(), "\n")
		lines[s.cursor+1] = selectedStyle.Render(lines[s.cursor+1])
		b.WriteString(strings.Join(lines, "\n"))
	}
	b.WriteString("\n\n" + dimStyle.Render("↑/↓ move") + "\n")
	if s.status != "" {
		b.WriteString("\n" + s.status)
	}
	return tea.NewView(strings.TrimRight(b.String(), "\n"))
}
