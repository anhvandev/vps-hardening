package tui

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/service"
)

func init() { screens["Timers"] = newTimers }

// timersScreen lists Timers read live, with their next run and target Service.
// n opens the new-Timer form (created, enabled and started on enter); E edits
// the selected Timer's override in $EDITOR, U reverts it (timers_edit.go).
type timersScreen struct {
	m      *harden.Machine
	loaded bool
	list   []service.Timer
	err    error // list unreadable
	cursor int
	status string
	form   []string  // new-Timer form values (timerFields), nil if closed
	field  int       // form field being typed into
	edit   *unitEdit // override being edited, nil if none
}

// timerFields are the new-Timer form's labels, in service.TimerSpec order.
var timerFields = []string{"Name", "Schedule", "Service"}

// timersMsg is one read of the Timers, plus the outcome of the last action.
type timersMsg struct {
	list   []service.Timer
	err    error
	status string
}

// timerCreatedMsg is a create finishing; unit is "" if nothing was created
// (the form stays open).
type timerCreatedMsg struct {
	timersMsg
	unit string
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
	if s, cmd, ok := s.editUpdate(msg); ok {
		return s, cmd
	}
	switch msg := msg.(type) {
	case timersMsg:
		s.list, s.err, s.status, s.loaded = msg.list, msg.err, msg.status, true
		s.cursor = max(min(s.cursor, len(s.list)-1), 0)
	case timerCreatedMsg:
		s.list, s.err, s.status = msg.list, msg.err, msg.status
		if msg.unit != "" {
			s.form = nil
			s.cursor = max(slices.IndexFunc(s.list, func(t service.Timer) bool { return t.Name == msg.unit }), 0)
		}
	case tea.KeyPressMsg:
		if s.form != nil {
			return s.formKey(msg)
		}
		switch msg.String() {
		case "esc":
			return s, Back
		case "up", "k":
			s.cursor = max(s.cursor-1, 0)
		case "down", "j":
			s.cursor = max(min(s.cursor+1, len(s.list)-1), 0)
		case "n":
			s.form, s.field, s.status = make([]string, len(timerFields)), 0, ""
		}
	}
	return s, nil
}

func (s timersScreen) formKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		s.form, s.status = nil, ""
	case "tab", "down":
		s.field = (s.field + 1) % len(s.form)
	case "shift+tab", "up":
		s.field = (s.field + len(s.form) - 1) % len(s.form)
	case "backspace":
		s.form[s.field] = dropLast(s.form[s.field])
	case "enter":
		return s, s.create(service.TimerSpec{Name: s.form[0], Schedule: s.form[1], Service: s.form[2]})
	default:
		s.form[s.field] += msg.Text
	}
	return s, nil
}

// create validates spec (a bad schedule or Service writes nothing and is not
// logged), then creates the Timer and enables and starts it, each under
// logMutation, and reports its next run.
func (s timersScreen) create(spec service.TimerSpec) tea.Cmd {
	r, root := s.m.R, s.m.Root
	return func() tea.Msg {
		unit, content, err := spec.Unit(r)
		if err != nil {
			return timerCreatedMsg{timersMsg{s.list, s.err, err.Error()}, ""}
		}
		err = logMutation(root, "timer create "+unit, func() error { return service.Create(r, root, unit, content) })
		created := err == nil
		if created {
			err = logMutation(root, "timer enable+start "+unit, func() error {
				if err := service.Do(r, "enable", unit); err != nil {
					return err
				}
				return service.Do(r, "start", unit)
			})
		}
		list, lerr := service.ListTimers(r)
		status := "created " + unit + ", next run "
		for _, t := range list {
			if t.Name == unit {
				status += cmp.Or(t.Next, "none")
			}
		}
		if err != nil {
			status = err.Error()
		}
		if !created {
			unit = ""
		}
		return timerCreatedMsg{timersMsg{list, lerr, status}, unit}
	}
}

func (s timersScreen) View() tea.View {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Timers") + "\n\n")
	switch {
	case !s.loaded:
		return tea.NewView(b.String() + "loading…")
	case s.form != nil:
		b.WriteString("New Timer\n\n")
		for i, label := range timerFields {
			mark, cursor := "  ", ""
			if i == s.field {
				mark, cursor = "> ", "█"
			}
			fmt.Fprintf(&b, "%s%-10s %s%s\n", mark, label, s.form[i], cursor)
		}
		b.WriteString("\n" + dimStyle.Render("schedule: systemd calendar syntax, e.g. daily, Mon *-*-* 03:00, *:0/15") + "\n")
		b.WriteString(dimStyle.Render("tab/↑/↓ field · enter create · esc cancel") + "\n\n" + s.status)
		return tea.NewView(strings.TrimRight(b.String(), "\n"))
	case s.err != nil:
		b.WriteString("Timers unreadable: " + s.err.Error())
	case len(s.list) == 0:
		b.WriteString("no Timers")
	default:
		var table strings.Builder
		tw := tabwriter.NewWriter(&table, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "Timer\tNext run\tService")
		for _, t := range s.list {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", t.Name, cmp.Or(t.Next, "-"), cmp.Or(t.Service, "-"))
		}
		tw.Flush()
		lines := strings.Split(table.String(), "\n")
		lines[s.cursor+1] = selectedStyle.Render(lines[s.cursor+1])
		b.WriteString(strings.Join(lines, "\n"))
	}
	b.WriteString("\n\n" + dimStyle.Render("↑/↓ move · n new · E edit · U revert") + "\n")
	if s.status != "" {
		b.WriteString("\n" + s.status)
	}
	return tea.NewView(strings.TrimRight(b.String(), "\n"))
}
