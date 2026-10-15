package tui

import (
	"cmp"
	"io"
	"slices"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/service"
	"github.com/anhvandev/vpsctl/internal/system"
)

func init() { screens["Timers"] = newTimers }

// timersScreen lists Timers read live, with their next run and target Service.
// a opens the new-Timer form (created, enabled and started as a Task); e edits
// the selected Timer's override in $EDITOR, U reverts it (unit_edit.go).
type timersScreen struct {
	m      *harden.Machine
	loaded bool
	list   []service.Timer
	err    error // list unreadable
	table  table
	status string
	form   *form     // new-Timer form, nil if closed
	edit   *unitEdit // override being edited, nil if none
	await  *awaited  // the create Task, until it ends
	asking bool      // the revert confirm is up
	ask    confirm
	pick   string // Timer to select once the list is re-read
	w, h   int
}

// timersMsg is one read of the Timers.
type timersMsg struct {
	list []service.Timer
	err  error
}

// timerInvalidMsg is the new-Timer form failing validation.
type timerInvalidMsg string

func newTimers(m *harden.Machine) tea.Model {
	return timersScreen{m: m, table: newTable("TIMER", "NEXT RUN", "SERVICE")}
}

func (s timersScreen) Init() tea.Cmd {
	return func() tea.Msg {
		list, err := service.ListTimers(s.m.R)
		return timersMsg{list, err}
	}
}

func (s timersScreen) flow() overrideFlow {
	return overrideFlow{s.m, "timer", "# An empty OnCalendar= first clears the vendor schedule.\n[Timer]\n"}
}

func (s timersScreen) selected() string {
	if i := s.table.selected(); i >= 0 {
		return s.list[i].Name
	}
	return ""
}

func (s timersScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		s.w, s.h = msg.Width, msg.Height
		s.table.height = max(s.h-14, 3)
		s.table.setRows(s.table.rows)
		return s, nil
	case timersMsg:
		s.list, s.err, s.loaded = msg.list, msg.err, true
		var rows [][]string
		for _, t := range s.list {
			rows = append(rows, []string{t.Name, cmp.Or(t.Next, "—"), cmp.Or(t.Service, "—")})
		}
		s.table.setRows(rows)
		if i := slices.IndexFunc(s.list, func(t service.Timer) bool { return t.Name == s.pick }); i >= 0 {
			s.table.filter.Reset()
			s.table.cursor, s.pick = i, ""
			s.table.setRows(rows)
		}
		return s, nil
	case timerInvalidMsg:
		if s.form != nil {
			s.form.err = string(msg)
		}
		s.await = nil
		return s, nil
	case taskDoneMsg:
		s.flow().done(&s.edit, &s.status)
		if a := s.await; a != nil {
			s.await = nil
			if a.ok.Load() {
				s.form, s.pick = nil, a.unit
			}
		}
		return s, s.Init()
	case tea.MouseClickMsg:
		if m := mouse(s.layout(), msg); m != nil {
			return s.Update(m)
		}
		return s, nil
	}
	if !s.table.typing() {
		if cmd, ok := s.flow().update(&s.edit, &s.status, msg); ok {
			return s, cmd
		}
	}
	switch {
	case s.form != nil:
		f, ev := s.form.update(msg)
		s.form = &f
		switch ev {
		case cancelled:
			s.form = nil
		case submitted:
			s.await = &awaited{what: "create"}
			return s, s.create(service.TimerSpec{Name: f.value(0), Schedule: f.value(1), Service: f.value(2)}, s.await)
		}
		return s, nil
	case s.asking:
		c, ev := s.ask.update(msg)
		s.ask, s.asking = c, ev == editing
		if ev == submitted {
			return s, s.flow().revert(s.selected())
		}
		return s, nil
	}
	if t, ok := s.table.update(msg); ok {
		s.table = t
		return s, nil
	}
	k, ok := msg.(tea.KeyPressMsg)
	if !ok || disabled(s.buttons(), k.String()) {
		return s, nil
	}
	switch k.String() {
	case "esc":
		return s, Back
	case "a":
		f := newForm("New Timer", "Name", "Schedule", "Service")
		f.inputs[1].Placeholder = "daily, Mon *-*-* 03:00, *:0/15"
		s.form, s.status = &f, ""
	case "e":
		return s, s.flow().start(&s.edit, &s.status, s.selected())
	case "U":
		s.asking, s.ask = true, newConfirm("Revert "+s.selected()+" override?")
	}
	return s, nil
}

// create validates spec (a bad schedule or Service writes nothing and is not
// logged), then creates, enables and starts the Timer as a Task.
// a.ok is set once the Timer is created.
func (s timersScreen) create(spec service.TimerSpec, a *awaited) tea.Cmd {
	r, root := s.m.R, s.m.Root
	return func() tea.Msg {
		unit, content, err := spec.Unit(r)
		if err != nil {
			return timerInvalidMsg(err.Error())
		}
		a.unit = unit
		return runTask("Create "+unit, "timer create "+unit, "created "+unit+", enabled and started",
			a.marks(taskStep{"Verify and load " + unit, func(r system.Runner, _ io.Writer) error {
				return service.Create(r, root, unit, content)
			}}),
			unitStep("enable", unit), unitStep("start", unit))()
	}
}

func (s timersScreen) typing() bool {
	return s.form != nil || s.table.typing()
}

func (s timersScreen) notice() string { return s.status }

func (s timersScreen) keys() string {
	switch {
	case s.edit != nil && s.edit.failed:
		return "enter re-edit · esc discard"
	case s.form != nil:
		return s.form.keys()
	case s.asking:
		return s.ask.keys()
	case s.table.typing():
		return s.table.keys()
	}
	return s.table.keys() + " · " + keyHelp(s.buttons()) + " · esc back"
}

func (s timersScreen) buttons() []button {
	unit := s.selected()
	edit := button{"e", "Edit", refusal(unit, "edit")}
	revert := button{"U", "Revert", edit.why}
	switch {
	case unit == "":
		edit.why, revert.why = "no Timer selected", "no Timer selected"
	case revert.why == "" && !hasOverride(s.m.Root, unit):
		revert.why = "no override to revert"
	}
	return []button{edit, revert, {"a", "+ New", ""}}
}

func (s timersScreen) layout() *lipgloss.Compositor {
	title := titleStyle.Render("Timers")
	switch {
	case !s.loaded:
		return stack(title, "", "loading…")
	case s.form != nil:
		hint := dimStyle.Render("schedule: systemd calendar syntax, e.g. daily, Mon *-*-* 03:00, *:0/15")
		return stack(title, "", s.form.view(), "", hint)
	}
	blocks := []any{title}
	if s.err != nil {
		blocks = append(blocks, "Timers unreadable: "+s.err.Error())
	} else {
		blocks = append(blocks, s.table.layer(s.w))
	}
	blocks = append(blocks, buttonRow(s.buttons()...))
	c := stack(blocks...)
	if s.asking {
		c.AddLayers(s.ask.layer(s.w))
	}
	return c
}

func (s timersScreen) View() tea.View { return tea.NewView(s.layout().Render()) }
