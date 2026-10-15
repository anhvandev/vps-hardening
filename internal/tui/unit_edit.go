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
	"github.com/anhvandev/vpsctl/internal/harden"
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
	create     bool   // path is a new unit: applied with service.Create
}

// editedMsg is the editor exiting; appliedMsg is the edit's apply finishing,
// with the screen's units re-read (its reload message).
type (
	editedMsg  struct{ err error }
	appliedMsg struct {
		reloaded tea.Msg
		ok       bool
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
	// The one deliberate exception to the system.Runner seam: the editor is
	// interactive and needs the real TTY, which only tea.ExecProcess hands over.
	c := exec.Command(args[0], append(args[1:], e.tmp)...)
	return tea.ExecProcess(c, func(err error) tea.Msg { return editedMsg{err} })
}

// close ends the edit: drops the temp copy and releases the global lock.
func (e *unitEdit) close() {
	os.Remove(e.tmp)
	e.lock.Close()
}

// overrideFlow is the override edit (E, in $EDITOR via unitEdit) and revert
// (U) flow shared by the Services and Timers screens.
type overrideFlow struct {
	m        *harden.Machine
	kind     string                      // "service" or "timer": the action-log label
	template string                      // a new override's body, after its header comment
	reload   func(status string) tea.Cmd // the screen's re-read of its units
}

// update runs the flow on the screen's edit in progress (*edit, nil if none)
// and status: the editor exiting, re-edit (enter) / discard (esc) after a
// failed apply, and E / U on unit ("" when none is selected or a form has the
// keys). ok is false for anything else. appliedMsg stays with the screen.
func (f overrideFlow) update(edit **unitEdit, status *string, msg tea.Msg, unit string) (_ tea.Cmd, ok bool) {
	e := *edit
	switch msg := msg.(type) {
	case editedMsg:
		content, err := os.ReadFile(e.tmp)
		switch {
		case msg.err != nil || err != nil:
			*status = "editor failed: " + cmp.Or(msg.err, err).Error()
		case string(content) == e.orig && !e.create:
			*status = "no changes to " + e.unit
		default:
			return f.apply(e, content), true
		}
		e.close()
		*edit = nil
		return nil, true
	case tea.KeyPressMsg:
		if e != nil && e.failed {
			switch msg.String() {
			case "enter":
				return e.open(), true
			case "esc":
				e.close()
				*status, *edit = "discarded edit of "+e.unit, nil
				return nil, true
			}
		}
		switch {
		case unit == "":
		case msg.String() == "E":
			if err := guard.Check(guard.Facts{}, guard.UnitAction{Unit: unit, Verb: "edit"}); err != nil {
				*status = err.Error()
				return nil, true
			}
			e, err := newUnitEdit(f.m.Root, unit, service.OverridePath(f.m.Root, unit),
				"# Override for "+unit+": settings here replace the vendor unit's.\n"+f.template)
			if err != nil {
				*status = err.Error()
				return nil, true
			}
			*edit = e
			return e.open(), true
		case msg.String() == "U":
			return f.revert(unit), true
		}
	}
	return nil, false
}

// revert removes unit's override under logMutation, then re-reads the units.
func (f overrideFlow) revert(unit string) tea.Cmd {
	return func() tea.Msg {
		err := logMutation(f.m.Root, f.kind+" revert "+unit, func() error {
			return service.Revert(f.m.R, f.m.Root, unit)
		})
		status := "reverted " + unit + " override, systemd reloaded"
		if err != nil {
			status = err.Error()
		}
		return f.reload(status)()
	}
}

// apply applies content as e's file, or creates it as a new unit, (under the
// edit's lock) and logs the result, then re-reads the units.
func (f overrideFlow) apply(e *unitEdit, content []byte) tea.Cmd {
	return func() tea.Msg {
		var err error
		status := "override for " + e.unit + " applied, systemd reloaded"
		if e.create {
			err = service.Create(f.m.R, f.m.Root, e.unit, content)
			appendLog(f.m.Root, f.kind+" create "+e.unit, err)
			status = "created " + e.unit + ", verified and loaded"
		} else {
			err = service.Apply(f.m.R, e.path, e.unit, content)
			appendLog(f.m.Root, f.kind+" edit "+e.unit, err)
		}
		if err != nil {
			status = err.Error() + "\nnothing applied · enter re-edit · esc discard"
		}
		return appliedMsg{f.reload(status)(), err == nil}
	}
}
