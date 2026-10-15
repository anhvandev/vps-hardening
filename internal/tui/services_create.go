package tui

import (
	"fmt"
	"slices"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/service"
)

// formFields are the new-Service form's labels, in service.Spec order.
var formFields = []string{"Name", "Description", "Command", "User", "Working directory", "Restart", "Environment"}

// serviceForm is the new-Service form: one value per formFields entry.
type serviceForm struct {
	values []string
	field  int // field being typed into
}

// createdMsg is a create or an enable+start finishing. unit is "" if the
// create failed (the form stays open); offer asks to enable and start it.
type createdMsg struct {
	servicesMsg
	unit  string
	offer bool
}

func (f *serviceForm) spec() service.Spec {
	v := f.values
	return service.Spec{Name: v[0], Description: v[1], Command: v[2], User: v[3], WorkingDir: v[4], Restart: v[5], Environment: v[6]}
}

// createUpdate runs the new-Service form (n), its create and the enable+start
// offer after it; ok is false for anything else.
func (s servicesScreen) createUpdate(msg tea.Msg) (_ servicesScreen, _ tea.Cmd, ok bool) {
	switch msg := msg.(type) {
	case createdMsg:
		s.list, s.err, s.status = msg.list, msg.err, msg.status
		if msg.unit != "" {
			s.form = nil
			if msg.offer {
				s.offer = msg.unit
			}
			s = s.selectUnit(msg.unit)
		}
		return s, nil, true
	case tea.KeyPressMsg:
		switch {
		case s.offer != "":
			unit := s.offer
			s.offer = ""
			if msg.String() == "y" {
				return s, s.enableStart(unit), true
			}
			s.status = "created " + unit + ", not enabled or started"
			return s, nil, true
		case s.form != nil:
			return s.formKey(msg)
		case msg.String() == "n" && !s.filtering:
			// The first Managed User (none: empty) so root is never picked by default.
			user := ""
			if users, err := s.m.ManagedUsers(); err == nil && len(users) > 0 {
				user = users[0].Name
			}
			s.form, s.status = &serviceForm{values: []string{"", "", "", user, "", "on-failure", ""}}, ""
			return s, nil, true
		}
	}
	return s, nil, false
}

func (s servicesScreen) formKey(msg tea.KeyPressMsg) (_ servicesScreen, _ tea.Cmd, ok bool) {
	f := s.form
	switch msg.String() {
	case "esc":
		s.form, s.status = nil, ""
	case "tab", "down":
		f.field = (f.field + 1) % len(f.values)
	case "shift+tab", "up":
		f.field = (f.field + len(f.values) - 1) % len(f.values)
	case "backspace":
		f.values[f.field] = dropLast(f.values[f.field])
	case "enter":
		unit, content, err := f.spec().Unit()
		if err != nil {
			s.status = err.Error()
			return s, nil, true
		}
		return s, s.create(unit, content), true
	case "ctrl+e": // Advanced: the generated unit in $EDITOR, created once saved
		unit, content, err := f.spec().Unit()
		if err != nil {
			s.status = err.Error()
			return s, nil, true
		}
		e, err := newUnitEdit(s.m.Root, unit, service.UnitPath(s.m.Root, unit), string(content))
		if err == nil {
			if err = service.CheckNew(s.m.R, s.m.Root, unit); err != nil {
				e.close()
			}
		}
		if err != nil {
			s.status = err.Error()
			return s, nil, true
		}
		e.create, s.edit = true, e
		return s, e.open(), true
	default:
		f.values[f.field] += msg.Text
	}
	return s, nil, true
}

// create writes the new unit under logMutation (verified, removed if invalid).
func (s servicesScreen) create(unit string, content []byte) tea.Cmd {
	return func() tea.Msg {
		err := logMutation(s.m.Root, "service create "+unit, func() error {
			return service.Create(s.m.R, s.m.Root, unit, content)
		})
		list, lerr := service.List(s.m.R)
		if err != nil {
			return createdMsg{servicesMsg{list, lerr, err.Error()}, "", false}
		}
		return createdMsg{servicesMsg{list, lerr, "created " + unit + ", verified and loaded"}, unit, true}
	}
}

// enableStart enables then starts a new unit under logMutation; on failure
// the operator is pointed at its journal (the unit is selected).
func (s servicesScreen) enableStart(unit string) tea.Cmd {
	return func() tea.Msg {
		err := logMutation(s.m.Root, "service enable+start "+unit, func() error { return service.EnableStart(s.m.R, unit) })
		list, lerr := service.List(s.m.R)
		status := "enabled and started " + unit
		if err != nil {
			status = err.Error() + "\nl opens " + unit + "'s journal"
		}
		for _, svc := range list {
			if err == nil && svc.Name == unit {
				status += ": " + state(svc)
			}
		}
		return createdMsg{servicesMsg{list, lerr, status}, unit, false}
	}
}

// selectUnit puts the cursor on unit, showing all Services if it is hidden.
func (s servicesScreen) selectUnit(unit string) servicesScreen {
	is := func(svc service.Service) bool { return svc.Name == unit }
	if !slices.ContainsFunc(s.shown(), is) {
		s.all, s.filter = true, ""
	}
	if i := slices.IndexFunc(s.shown(), is); i >= 0 {
		s.cursor = i
	}
	s.cursor = max(min(s.cursor, len(s.shown())-1), 0)
	return s
}

func (f *serviceForm) view() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("New Service") + "\n\n")
	for i, label := range formFields {
		mark, cursor := "  ", ""
		if i == f.field {
			mark, cursor = "> ", "█"
		}
		fmt.Fprintf(&b, "%s%-18s %s%s\n", mark, label, f.values[i], cursor)
	}
	b.WriteString("\n" + dimStyle.Render("restart: "+strings.Join(service.RestartPolicies, ", ")+" · user root only if typed explicitly") + "\n")
	b.WriteString(dimStyle.Render("tab/↑/↓ field · enter create · ctrl+e advanced ($EDITOR) · esc cancel") + "\n")
	return b.String()
}
