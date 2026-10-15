package tui

// The Hardening Status (design §2a): each Hardening Step read live as Done,
// Missing or Skipped, with what the Hardening Record remembers. A Missing or
// Skipped step can be applied alone (or all Missing ones), each as a Task;
// the SSH port and key rows link to the SSH and Users screens instead.

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/anhvandev/vpsctl/internal/guard"
	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
	"github.com/anhvandev/vpsctl/internal/user"
)

// hardeningMsg is the Hardening Status read for the Hardening screen;
// lockWhy is why the Lockout Guard refuses locking the Default Cloud Users.
type hardeningMsg struct {
	steps   []harden.Step
	rec     *harden.Record
	lockWhy string
}

// cloudUsersAdmin is the Admin User that keeps the operator in once the
// Default Cloud Users in users are locked, or the Lockout Guard's refusal:
// never lock the session's own user or the last usable Admin User.
func cloudUsersAdmin(users []user.ManagedUser, rec *harden.Record) (string, error) {
	f := guard.Facts{SessionUser: system.SessionUser(), Users: slices.Clone(users)}
	for i, u := range f.Users { // one by one: each lock counts for the next
		if slices.Contains(user.DefaultCloudUsers, u.Name) {
			if err := guard.Check(f, guard.UserAction{User: u.Name, Verb: "lock"}); err != nil {
				return "", err
			}
			f.Users[i].Locked = true
		}
	}
	admin, ok := harden.AdminUser(users, rec)
	if !ok {
		return "", errors.New("refused: no usable Admin User would be left to log in as")
	}
	return admin.Name, nil
}

// lockCloudUsers is the cloud-users step under the lock: the Lockout Guard
// on live facts, then the full run's pre-lock assertions for the Admin User
// (through tm, the step's Machine), then the lock.
func lockCloudUsers(m, tm *harden.Machine) error {
	users, err := m.ManagedUsers() // through m: shadow stays out of the output
	if err != nil {
		return err
	}
	rec, _ := harden.LoadRecord(m.Root)
	admin, err := cloudUsersAdmin(users, rec)
	if err != nil {
		return err
	}
	if err := tm.PreLockAssertions(admin); err != nil {
		return fmt.Errorf("pre-lock assertion failed: %w", err)
	}
	return tm.LockDefaultCloudUsers()
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
	"cloud-users": (*harden.Machine).LockDefaultCloudUsers, // guarded: apply runs lockCloudUsers
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
	if h.applicable(s) && h.refusal(s) == "" {
		return h, h.apply("Apply "+s.Name, s)
	}
	return h, nil
}

// applicable: s is not Done and Apply can fix it.
func (h hardening) applicable(s harden.Step) bool {
	return s.State != harden.Done && stepApply[s.ID] != nil
}

// refusal is why the Lockout Guard refuses applying s, "" if it allows it.
func (h hardening) refusal(s harden.Step) string {
	if s.ID == "cloud-users" {
		return h.lockWhy
	}
	return ""
}

// missing are the Missing steps Apply can fix (Skipped ones stay a choice)
// and the Lockout Guard allows.
func (h hardening) missing() []harden.Step {
	var ms []harden.Step
	for _, s := range h.steps {
		if s.State == harden.Missing && h.applicable(s) && h.refusal(s) == "" {
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
			tm, do := taskMachine(h.m, r), stepApply[s.ID]
			if s.ID == "cloud-users" {
				do = func(tm *harden.Machine) error { return lockCloudUsers(h.m, tm) }
			}
			if err := do(tm); err != nil {
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
		} else if why := h.refusal(s); h.applicable(s) && why != "" { // disabled, with the Lockout Guard's reason
			btn, detail = naStyle.Render("[ Apply ]"), strings.TrimPrefix(why, "refused: ")
		} else if h.applicable(s) {
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
