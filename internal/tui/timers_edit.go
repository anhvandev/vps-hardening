package tui

import (
	"cmp"
	"os"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/service"
)

// timerAppliedMsg is an override edit's apply finishing.
type timerAppliedMsg struct {
	timersMsg
	ok bool
}

// editUpdate runs the override edit (E, in $EDITOR via unitEdit) and revert
// (U) keys and their messages, as on the Services screen; ok is false for
// anything else.
func (s timersScreen) editUpdate(msg tea.Msg) (_ timersScreen, _ tea.Cmd, ok bool) {
	switch msg := msg.(type) {
	case editedMsg:
		content, err := os.ReadFile(s.edit.tmp)
		switch {
		case msg.err != nil || err != nil:
			s.status = "editor failed: " + cmp.Or(msg.err, err).Error()
		case string(content) == s.edit.orig:
			s.status = "no changes to " + s.edit.unit
		default:
			return s, s.applyEdit(content), true
		}
		s.edit.close()
		s.edit = nil
		return s, nil, true
	case timerAppliedMsg:
		s.list, s.err, s.status = msg.list, msg.err, msg.status
		if msg.ok {
			s.edit.close()
			s.edit = nil
		} else {
			s.edit.failed = true
		}
		return s, nil, true
	case tea.KeyPressMsg:
		if s.form != nil {
			return s, nil, false
		}
		if s.edit != nil && s.edit.failed {
			switch msg.String() {
			case "enter":
				return s, s.edit.open(), true
			case "esc":
				s.edit.close()
				s.status, s.edit = "discarded edit of "+s.edit.unit, nil
				return s, nil, true
			}
		}
		if s.cursor >= len(s.list) {
			return s, nil, false
		}
		unit := s.list[s.cursor].Name
		switch msg.String() {
		case "E":
			e, err := newUnitEdit(s.m.Root, unit, service.OverridePath(s.m.Root, unit),
				"# Override for "+unit+": settings here replace the vendor unit's.\n"+
					"# An empty OnCalendar= first clears the vendor schedule.\n[Timer]\n")
			if err != nil {
				s.status = err.Error()
				return s, nil, true
			}
			s.edit = e
			return s, e.open(), true
		case "U":
			return s, s.revert(unit), true
		}
	}
	return s, nil, false
}

// revert removes unit's override under logMutation, then re-reads the Timers.
func (s timersScreen) revert(unit string) tea.Cmd {
	return func() tea.Msg {
		err := logMutation(s.m.Root, "timer revert "+unit, func() error {
			return service.Revert(s.m.R, s.m.Root, unit)
		})
		list, lerr := service.ListTimers(s.m.R)
		status := "reverted " + unit + " override, systemd reloaded"
		if err != nil {
			status = err.Error()
		}
		return timersMsg{list, lerr, status}
	}
}

// applyEdit applies content as the edit's override (under the edit's lock)
// and logs the result, then re-reads the Timers.
func (s timersScreen) applyEdit(content []byte) tea.Cmd {
	e := s.edit
	return func() tea.Msg {
		err := service.Apply(s.m.R, e.path, e.unit, content)
		appendLog(s.m.Root, "timer edit "+e.unit, err)
		list, lerr := service.ListTimers(s.m.R)
		status := "override for " + e.unit + " applied, systemd reloaded"
		if err != nil {
			status = err.Error() + "\nnothing applied · enter re-edit · esc discard"
		}
		return timerAppliedMsg{timersMsg{list, lerr, status}, err == nil}
	}
}
