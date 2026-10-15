package tui

import (
	"cmp"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/actionlog"
	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/service"
	"github.com/anhvandev/vpsctl/internal/system"
)

// unitEdit is an edit of the unit file or drop-in at path, made in $EDITOR on
// a temp copy and applied as a Task with service.Apply (verify, then reload).
// The global lock is held while the editor is open (the Task takes it
// next). Until the apply succeeds the copy is kept so the operator can
// re-edit or discard it.
type unitEdit struct {
	unit, path string
	lock       *os.File // held while the editor is open, else nil
	tmp        string   // the copy the editor works on
	orig       string   // path's content (or template) before editing
	failed     bool     // saved but not applied: enter re-edits, esc discards
	create     bool     // path is a new unit: applied with service.Create
	applied    atomic.Bool
}

// editedMsg is the editor exiting.
type editedMsg struct{ err error }

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

// unlock releases the global lock if the edit holds it.
func (e *unitEdit) unlock() {
	if e.lock != nil {
		e.lock.Close()
		e.lock = nil
	}
}

// close ends the edit: drops the temp copy and releases the global lock.
func (e *unitEdit) close() {
	os.Remove(e.tmp)
	e.unlock()
}

// overrideFlow is the override edit (in $EDITOR via unitEdit) and revert
// flow shared by the Services and Timers screens, on the screen's edit in
// progress (*edit, nil if none) and status line.
type overrideFlow struct {
	m        *harden.Machine
	kind     string // "service" or "timer": the Task History label
	template string // a new override's body, after its header comment
}

// start opens unit's override in the editor; a busy lock refuses it.
func (f overrideFlow) start(edit **unitEdit, status *string, unit string) tea.Cmd {
	e, err := newUnitEdit(f.m.Root, unit, service.OverridePath(f.m.Root, unit),
		"# Override for "+unit+": settings here replace the vendor unit's.\n"+f.template)
	if err != nil {
		*status = err.Error()
		return nil
	}
	*edit, *status = e, ""
	return e.open()
}

// create opens content, a new unit, in the editor; it is created once saved.
func (f overrideFlow) create(edit **unitEdit, unit, content string) (tea.Cmd, error) {
	e, err := newUnitEdit(f.m.Root, unit, service.UnitPath(f.m.Root, unit), content)
	if err == nil {
		if err = service.CheckNew(f.m.R, f.m.Root, unit); err != nil {
			e.close()
		}
	}
	if err != nil {
		return nil, err
	}
	e.create, *edit = true, e
	return e.open(), nil
}

// update runs the editor exiting (a changed copy is applied as a Task) and
// re-edit (enter) / discard (esc) of a copy not applied; ok is false for
// anything else.
func (f overrideFlow) update(edit **unitEdit, status *string, msg tea.Msg) (_ tea.Cmd, ok bool) {
	e := *edit
	if e == nil {
		return nil, false
	}
	switch msg := msg.(type) {
	case editedMsg:
		e.unlock()
		content, err := os.ReadFile(e.tmp)
		switch {
		case msg.err != nil || err != nil:
			*status = "editor failed: " + cmp.Or(msg.err, err).Error()
		case string(content) == e.orig && !e.create:
			*status = "no changes to " + e.unit
		default:
			e.failed, *status = true, ""
			return f.apply(e, content), true
		}
		e.close()
		*edit = nil
		return nil, true
	case tea.KeyPressMsg:
		if !e.failed {
			return nil, false
		}
		switch msg.String() {
		case "enter":
			lk, err := actionlog.Lock(filepath.Join(f.m.Root, actionlog.LockPath))
			if err != nil {
				*status = err.Error()
				return nil, true
			}
			e.lock = lk
			return e.open(), true
		case "esc":
			e.close()
			*status, *edit = "discarded edit of "+e.unit, nil
			return nil, true
		}
	}
	return nil, false
}

// done is a Task ending: once the edit's apply succeeded the edit is closed,
// returning the unit if it was created; otherwise the copy stays.
func (f overrideFlow) done(edit **unitEdit, status *string) (created string) {
	e := *edit
	if e == nil || !e.failed {
		return ""
	}
	if !e.applied.Load() {
		*status = "nothing applied · enter re-edit · esc discard"
		return ""
	}
	e.close()
	*edit, *status = nil, ""
	if e.create {
		return e.unit
	}
	return ""
}

// revert removes unit's override as a Task.
func (f overrideFlow) revert(unit string) tea.Cmd {
	return runTask("Revert "+unit+" override", f.kind+" revert "+unit, "reverted "+unit+" override, systemd reloaded",
		taskStep{"Remove the override and reload", func(r system.Runner, _ io.Writer) error {
			return service.Revert(r, f.m.Root, unit)
		}})
}

// apply applies content as e's file, or creates it as a new unit, as a Task.
func (f overrideFlow) apply(e *unitEdit, content []byte) tea.Cmd {
	step := taskStep{"Verify and reload", func(r system.Runner, _ io.Writer) error {
		err := service.Apply(r, e.path, e.unit, content)
		e.applied.Store(err == nil)
		return err
	}}
	if e.create {
		step.do = func(r system.Runner, _ io.Writer) error {
			err := service.Create(r, f.m.Root, e.unit, content)
			e.applied.Store(err == nil)
			return err
		}
		return runTask("Create "+e.unit, f.kind+" create "+e.unit, "created "+e.unit+", verified and loaded", step)
	}
	return runTask("Edit "+e.unit+" override", f.kind+" edit "+e.unit, "override for "+e.unit+" applied, systemd reloaded", step)
}
