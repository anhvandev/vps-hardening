package tui

import (
	"cmp"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/actionlog"
	"github.com/anhvandev/vpsctl/internal/guard"
	"github.com/anhvandev/vpsctl/internal/service"
)

// unitEdit is an edit of the unit file or drop-in at path, made in $EDITOR on
// a temp copy and applied with service.Apply (verify, then reload). After a
// failed apply the copy is kept so the operator can re-edit or discard it.
// The global lock is held from before the editor opens until close.
type unitEdit struct {
	unit, path string
	lock       *os.File
	tmp        string // the copy the editor works on
	orig       string // path's content (or template) before editing
	failed     bool   // the last apply failed: enter re-edits, esc discards
}

// editedMsg is the editor exiting; appliedMsg is the edit's apply finishing.
type (
	editedMsg  struct{ err error }
	appliedMsg struct {
		servicesMsg
		ok bool
	}
)

// newUnitEdit takes the global lock under root and copies path's content, or
// template if it has none, to a temp file for the editor. A busy lock returns
// its holder.
func newUnitEdit(root, unit, path, template string) (*unitEdit, error) {
	lk, err := actionlog.Lock(filepath.Join(root, actionlog.LockPath))
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		b = []byte(template)
	}
	f, err := os.CreateTemp("", "vpsctl-*-"+unit)
	if err != nil {
		lk.Close()
		return nil, err
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		os.Remove(f.Name())
		lk.Close()
		return nil, err
	}
	return &unitEdit{unit: unit, path: path, lock: lk, tmp: f.Name(), orig: string(b)}, nil
}

// open hands the terminal to $EDITOR (nano if unset) on the temp copy.
func (e *unitEdit) open() tea.Cmd {
	args := strings.Fields(cmp.Or(os.Getenv("EDITOR"), "nano"))
	c := exec.Command(args[0], append(args[1:], e.tmp)...)
	return tea.ExecProcess(c, func(err error) tea.Msg { return editedMsg{err} })
}

// close ends the edit: drops the temp copy and releases the global lock.
func (e *unitEdit) close() {
	os.Remove(e.tmp)
	e.lock.Close()
}

// editUpdate runs the override edit/revert keys and messages; ok is false for
// anything else.
func (s servicesScreen) editUpdate(msg tea.Msg) (_ servicesScreen, _ tea.Cmd, ok bool) {
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
	case appliedMsg:
		s.list, s.err, s.status = msg.list, msg.err, msg.status
		if msg.ok {
			s.edit.close()
			s.edit = nil
		} else {
			s.edit.failed = true
		}
		return s, nil, true
	case tea.KeyPressMsg:
		if s.filtering {
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
		if msg.String() == "E" && s.cursor < len(s.shown()) {
			unit := s.shown()[s.cursor].Name
			if err := guard.Check(guard.Facts{}, guard.UnitAction{Unit: unit, Verb: "edit"}); err != nil {
				s.status = err.Error()
				return s, nil, true
			}
			e, err := newUnitEdit(s.m.Root, unit, service.OverridePath(s.m.Root, unit),
				"# Override for "+unit+": settings here replace the vendor unit's.\n[Service]\n")
			if err != nil {
				s.status = err.Error()
				return s, nil, true
			}
			s.edit = e
			return s, e.open(), true
		}
		if msg.String() == "U" && s.cursor < len(s.shown()) {
			return s, s.revert(s.shown()[s.cursor].Name), true
		}
	}
	return s, nil, false
}

// revert removes unit's override under logMutation, then re-reads the Services.
func (s servicesScreen) revert(unit string) tea.Cmd {
	return func() tea.Msg {
		err := logMutation(s.m.Root, "service revert "+unit, func() error {
			return service.Revert(s.m.R, s.m.Root, unit)
		})
		list, lerr := service.List(s.m.R)
		status := "reverted " + unit + " override, systemd reloaded"
		if err != nil {
			status = err.Error()
		}
		return servicesMsg{list, lerr, status}
	}
}

// applyEdit applies content as the edit's file (under the edit's lock) and
// logs the result, then re-reads the Services.
func (s servicesScreen) applyEdit(content []byte) tea.Cmd {
	e := s.edit
	return func() tea.Msg {
		err := service.Apply(s.m.R, e.path, e.unit, content)
		appendLog(s.m.Root, "service edit "+e.unit, err)
		list, lerr := service.List(s.m.R)
		status := "override for " + e.unit + " applied, systemd reloaded"
		if err != nil {
			status = err.Error() + "\nnothing applied · enter re-edit · esc discard"
		}
		return appliedMsg{servicesMsg{list, lerr, status}, err == nil}
	}
}
