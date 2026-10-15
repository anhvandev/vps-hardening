package tui

// The Hardening Status (design §2a): each Hardening Step read live as Done,
// Missing or Skipped, with what the Hardening Record remembers. Read-only.

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/anhvandev/vpsctl/internal/harden"
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
		if m := mouse(h.layout(), click); m != nil {
			return h.statusUpdate(m)
		}
		return h, nil
	}
	if t, ok := h.table.update(msg); ok {
		h.table = t
		return h, nil
	}
	switch k, _ := msg.(tea.KeyPressMsg); k.String() {
	case "esc":
		return h, Back
	case "r":
		return h, h.Init()
	}
	return h, nil
}

// typing: the wizard is a text form; the Status only while filtering.
func (h hardening) typing() bool { return !h.hst || h.table.typing() }

func (h hardening) keys() string {
	switch {
	case !h.hst:
		return "esc back · ctrl+c quit"
	case h.table.typing():
		return h.table.keys()
	}
	return h.table.keys() + " · r refresh · esc back"
}

// rows are the table rows, one per Hardening Step.
func (h hardening) rows() [][]string {
	var rows [][]string
	for _, s := range h.steps {
		state, detail := okStyle.Render(glyph("●")+" Done"), s.Detail
		switch s.State {
		case harden.Missing:
			state = warnStyle.Render(glyph("⚠") + " Missing")
			if !s.Applied.IsZero() {
				detail = strings.TrimPrefix(detail+" · was applied "+s.Applied.Format("2006-01-02"), " · ")
			}
		case harden.Skipped:
			state, detail = naStyle.Render(glyph("·")+" Skipped"), "chosen at Hardening"
		}
		rows = append(rows, []string{s.Name, state, detail})
	}
	return rows
}

// layout is the header (when Hardening ran, by whom, the Admin User) and
// the steps table.
func (h hardening) layout() *lipgloss.Compositor {
	title, note := titleStyle.Render("Hardening"), dimStyle.Render("no Hardening Record")
	if r := h.rec; r != nil {
		note = "ran " + r.Ran.Format("2006-01-02 15:04") + " by " + r.By + " · Admin User " + r.Admin
	}
	head := title + strings.Repeat(" ", max(h.w-ansi.StringWidth(title)-ansi.StringWidth(note), 1)) + note
	return stack(head, h.table.layer(h.w))
}
