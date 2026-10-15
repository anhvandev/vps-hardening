package tui

import (
	"io"
	"slices"
	"sync/atomic"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/service"
	"github.com/anhvandev/vpsctl/internal/system"
)

// formFields are the new-Service form's labels, in service.Spec order.
var formFields = []string{"Name", "Description", "Command", "User", "Working directory", "Restart", "Environment"}

// awaited is a Task whose result a screen acts on once it ends (taskDoneMsg
// says only that some Task ended): what it was, for unit, and ok, set by its
// step when that succeeds.
type awaited struct {
	what, unit string
	ok         atomic.Bool
}

// marks is step s, setting a.ok when it succeeds.
func (a *awaited) marks(s taskStep) taskStep {
	return taskStep{s.name, func(r system.Runner, out io.Writer) error {
		err := s.do(r, out)
		a.ok.Store(err == nil)
		return err
	}}
}

// openForm opens the new-Service form, its User the first Managed User
// (none: empty) so root is never picked by default.
func (s servicesScreen) openForm() servicesScreen {
	f := newForm("New Service", formFields...)
	if users, err := s.m.ManagedUsers(); err == nil && len(users) > 0 {
		f.inputs[3].SetValue(users[0].Name)
	}
	f.inputs[5].SetValue("on-failure")
	s.form, s.status = &f, ""
	return s
}

func (s servicesScreen) spec() service.Spec {
	v := s.form.value
	return service.Spec{Name: v(0), Description: v(1), Command: v(2), User: v(3), WorkingDir: v(4), Restart: v(5), Environment: v(6)}
}

// formUpdate edits the form: enter creates the Service as a Task, ctrl+e
// (Advanced) opens the generated unit in $EDITOR first; the form stays open
// until the create succeeds.
func (s servicesScreen) formUpdate(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyPressMsg); ok && k.String() == "ctrl+e" {
		unit, content, err := s.spec().Unit()
		if err == nil {
			var cmd tea.Cmd
			cmd, err = s.flow().create(&s.edit, unit, string(content))
			if err == nil {
				return s, cmd
			}
		}
		s.form.err = err.Error()
		return s, nil
	}
	f, ev := s.form.update(msg)
	s.form = &f
	switch ev {
	case cancelled:
		s.form = nil
	case submitted:
		unit, content, err := s.spec().Unit()
		if err != nil {
			s.form.err = err.Error()
			return s, nil
		}
		s.await = &awaited{what: "create", unit: unit}
		return s, runTask("Create "+unit, "service create "+unit, "created "+unit+", verified and loaded",
			s.await.marks(taskStep{"Verify and load " + unit, func(r system.Runner, _ io.Writer) error {
				return service.Create(r, s.m.Root, unit, content)
			}}))
	}
	return s, nil
}

// enableStart enables then starts a new unit as a Task, marking a.
func enableStart(a *awaited) tea.Cmd {
	return runTask("Enable and start "+a.unit, "service enable+start "+a.unit, "enabled and started "+a.unit,
		unitStep("enable", a.unit), a.marks(unitStep("start", a.unit)))
}

// selectUnit puts the selection on unit, showing all Services if it is hidden.
func (s servicesScreen) selectUnit(unit string) servicesScreen {
	is := func(svc service.Service) bool { return svc.Name == unit }
	if !slices.ContainsFunc(s.units(), is) {
		s.all = true
	}
	s.table.filter.Reset()
	s.table.setRows(s.rows())
	if i := slices.IndexFunc(s.units(), is); i >= 0 {
		s.table.cursor = i
		s.table.setRows(s.table.rows)
	}
	return s
}
