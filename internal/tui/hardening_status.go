package tui

// The Hardening Status (design §2a): each Hardening Step read live as Done,
// Missing or Skipped, with what the Hardening Record remembers. A Missing or
// Skipped step can be applied alone (or all Missing ones), each as a Task;
// the SSH port and key rows link to the SSH and Users screens instead.

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

// hardeningMsg is the Hardening Status read for the Hardening screen.
type hardeningMsg struct {
	steps []harden.Step
	rec   *harden.Record
}

// readHardening re-reads the Hardening Status behind the header badge: SSH
// key-only, and steps Done of those not Skipped.
// ponytail: runs every step check (~10 commands) inside Update; move it to a
// Cmd once the test Runners are safe for concurrent use.
func (t *Model) readHardening() {
	rec, _ := harden.LoadRecord(t.m.Root)
	t.done, t.chosen = 0, 0
	for _, s := range t.m.Status(rec) {
		if s.ID == "ssh" {
			t.hardened = s.State == harden.Done
		}
		if s.State != harden.Skipped {
			t.chosen++
		}
		if s.State == harden.Done {
			t.done++
		}
	}
}

func (h hardening) statusUpdate(msg tea.Msg) (tea.Model, tea.Cmd) {
	if click, ok := msg.(tea.MouseClickMsg); ok {
		m := mouse(h.layout(), click)
		if row, ok := m.(rowMsg); ok { // a click on a row's button presses it
			h.table, _ = h.table.update(row)
			lines := strings.Split(h.layout().Render(), "\n")
			if click.Y < len(lines) && buttonAt(ansi.Strip(lines[click.Y]), click.X) != "" {
				return h.act()
			}
			return h, nil
		}
		if m != nil {
			return h.statusUpdate(m)
		}
		return h, nil
	}
	if t, ok := h.table.update(msg); ok {
		h.table = t
		return h, nil
	}
	k, _ := msg.(tea.KeyPressMsg)
	if disabled(h.buttons(), k.String()) {
		return h, nil
	}
	switch k.String() {
	case "esc":
		return h, Back
	case "r":
		return h, h.Init()
	case "enter":
		return h.act()
	case "a":
		return h, h.apply("Apply all missing", h.missing()...)
	}
	return h, nil
}

// stepLinks are the steps changed on another screen, with their button.
var stepLinks = map[string]struct{ screen, label string }{
	"admin": {"Users", "Keys in Users"},
	"port":  {"SSH", "Change in SSH"},
}

// stepApply applies one Hardening Step alone, the way Hardening does.
var stepApply = map[string]func(*harden.Machine) error{
	"firewall": func(m *harden.Machine) error {
		port, err := m.CurrentPort()
		if err == nil {
			_, err = m.EnsureFirewall(port)
		}
		return err
	},
	"cloud-users": (*harden.Machine).LockDefaultCloudUsers,
	"cloud-init":  (*harden.Machine).BlockCloudInitReinjection,
	"fail2ban": func(m *harden.Machine) error {
		port, err := m.CurrentPort()
		if err != nil {
			return err
		}
		return m.Fail2ban(port)
	},
	"updates": (*harden.Machine).AutoUpdates,
	"sysctl":  (*harden.Machine).Sysctl,
}

// act presses the selected row's button: Apply, or open the linked screen.
func (h hardening) act() (tea.Model, tea.Cmd) {
	i := h.table.selected()
	if i < 0 {
		return h, nil
	}
	s := h.steps[i]
	if l, ok := stepLinks[s.ID]; ok {
		return h, func() tea.Msg { return openMsg{title: l.screen} }
	}
	if s.State != harden.Done && stepApply[s.ID] != nil {
		return h, h.apply("Apply "+s.Name, s)
	}
	return h, nil
}

// missing are the Missing steps Apply can fix (Skipped ones stay a choice).
func (h hardening) missing() []harden.Step {
	var ms []harden.Step
	for _, s := range h.steps {
		if s.State == harden.Missing && stepApply[s.ID] != nil {
			ms = append(ms, s)
		}
	}
	return ms
}

// apply is the Task applying steps, each then recorded as applied (and no
// longer Skipped) in the Hardening Record.
func (h hardening) apply(name string, steps ...harden.Step) tea.Cmd {
	var ids, names []string
	var ts []taskStep
	for _, s := range steps {
		ids, names = append(ids, s.ID), append(names, s.Name)
		ts = append(ts, taskStep{s.Name, func(r system.Runner, _ io.Writer) error {
			if err := stepApply[s.ID](taskMachine(h.m, r)); err != nil {
				return err
			}
			return recordApplied(h.m.Root, s.ID)
		}})
	}
	return runTask(name, "harden apply "+strings.Join(ids, " "), strings.Join(names, ", ")+" applied", ts...)
}

// recordApplied marks step id applied now, and no longer Skipped, in the
// Hardening Record under root (creating one).
func recordApplied(root, id string) error {
	rec, err := harden.LoadRecord(root)
	if err != nil {
		return fmt.Errorf("hardening record: %w", err)
	}
	if rec == nil {
		rec = &harden.Record{}
	}
	if rec.Applied == nil {
		rec.Applied = map[string]time.Time{}
	}
	rec.Applied[id] = time.Now()
	rec.Skipped = slices.DeleteFunc(rec.Skipped, func(s string) bool { return s == id })
	return rec.Save(root)
}

func (h hardening) buttons() []button {
	all := button{"a", "Apply all missing", ""}
	if len(h.missing()) == 0 {
		all.why = "nothing Missing to apply"
	}
	return []button{all}
}

// typing: the wizard is a text form; the Status only while filtering.
func (h hardening) typing() bool { return !h.hst || h.table.typing() }

func (h hardening) keys() string {
	switch {
	case !h.hst:
		return h.form.keys()
	case h.table.typing():
		return h.table.keys()
	}
	return h.table.keys() + " · enter apply/open · " + keyHelp(h.buttons()) + " · r refresh · esc back"
}

// rows are the table rows, one per Hardening Step, with its button.
func (h hardening) rows() [][]string {
	var rows [][]string
	for _, s := range h.steps {
		state, detail, btn := okStyle.Render(glyph("●")+" Done"), s.Detail, ""
		switch s.State {
		case harden.Missing:
			state = warnStyle.Render(glyph("⚠") + " Missing")
			if !s.Applied.IsZero() {
				detail = strings.TrimPrefix(detail+" · was applied "+s.Applied.Format("2006-01-02"), " · ")
			}
		case harden.Skipped:
			state, detail = naStyle.Render(glyph("·")+" Skipped"), "chosen at Hardening"
		}
		if l, ok := stepLinks[s.ID]; ok {
			btn = "[ " + l.label + " ]"
		} else if s.State != harden.Done && stepApply[s.ID] != nil {
			btn = "[ Apply ]"
		}
		rows = append(rows, []string{s.Name, state, detail, btn})
	}
	return rows
}

// statusLayout is the header (when Hardening ran, by whom, the Admin User), the
// steps table and Apply all missing.
func (h hardening) statusLayout() *lipgloss.Compositor {
	title, note := titleStyle.Render("Hardening"), dimStyle.Render("no Hardening Record")
	if r := h.rec; r != nil && !r.Ran.IsZero() { // per-step Apply alone records no run
		note = "ran " + r.Ran.Format("2006-01-02 15:04") + " by " + r.By + " · Admin User " + r.Admin
	}
	head := title + strings.Repeat(" ", max(h.w-ansi.StringWidth(title)-ansi.StringWidth(note), 1)) + note
	return stack(head, h.table.layer(h.w), buttonRow(h.buttons()...))
}
