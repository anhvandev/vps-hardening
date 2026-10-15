package tui

import (
	"fmt"
	"io"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

func init() { screens["Hardening"] = newHardening }

// hardenField is one wizard input, mapped to its `vpsctl harden` flag: a
// text value (blank = flag left out) or a toggle.
type hardenField struct {
	label, flag string
	toggle      bool
	value       string
	on          bool
}

// hardening is the Hardening screen. On a machine whose SSH is key-only it
// is the Hardening Status (hardening_status.go); otherwise the wizard: the
// inputs of `vpsctl harden`, checked by the same harden.ParseFlags, then
// Hardening as a Task whose steps are the Hardening Steps, with the Verify
// Gate in its panel and the private key shown raw outside the TUI
// (rawKeyMachine) or written to the key file.
type hardening struct {
	m      *harden.Machine
	loaded bool           // the Hardening Status was read
	steps  []harden.Step  // the Hardening Status
	rec    *harden.Record // nil without a Hardening Record
	hst    bool           // the Hardening Status shows, not the wizard
	table  table
	w, ht  int
	fields []hardenField
	cursor int
	status string // an input error
}

func newHardening(m *harden.Machine) tea.Model {
	return hardening{m: m, table: newTable("STEP", "STATE", "", ""), fields: []hardenField{
		{label: "Admin user", flag: "--user"},
		{label: "SSH port (blank = keep current)", flag: "--port"},
		{label: "Key file, mode 600 (blank = show on screen)", flag: "--key-out"},
		{label: "Rotate key", flag: "--rotate-key", toggle: true},
		{label: "Skip firewall", flag: "--skip-firewall", toggle: true},
		{label: "Skip fail2ban", flag: "--skip-fail2ban", toggle: true},
		{label: "Skip automatic updates", flag: "--skip-updates", toggle: true},
		{label: "Skip sysctl", flag: "--skip-sysctl", toggle: true},
	}}
}

func (h hardening) Init() tea.Cmd {
	return func() tea.Msg {
		rec, _ := harden.LoadRecord(h.m.Root) // unreadable = none: live checks still tell Done/Missing
		return hardeningMsg{h.m.Status(rec), rec}
	}
}

func (h hardening) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case hardeningMsg:
		h.loaded, h.steps, h.rec = true, msg.steps, msg.rec
		h.hst = msg.steps[1].State == harden.Done // key-only SSH
		h.table.setRows(h.rows())
		return h, nil
	case taskDoneMsg:
		return h, h.Init()
	case tea.WindowSizeMsg:
		h.w, h.ht = msg.Width, msg.Height
		return h, nil
	}
	if h.hst {
		return h.statusUpdate(msg)
	}
	if k, ok := msg.(tea.KeyPressMsg); ok {
		return h.key(k)
	}
	return h, nil
}

// key edits the form: ↑/↓ move, text fields take typing, space flips a
// toggle, enter validates and runs.
func (h hardening) key(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	f := &h.fields[h.cursor]
	switch k := msg.String(); {
	case k == "esc":
		return h, Back
	case k == "up" || k == "shift+tab":
		h.cursor = max(h.cursor-1, 0)
	case k == "down" || k == "tab":
		h.cursor = min(h.cursor+1, len(h.fields)-1)
	case k == "enter":
		return h.start()
	case f.toggle:
		if k == "space" {
			f.on = !f.on
		}
	case k == "backspace":
		f.value = dropLast(f.value)
	default:
		f.value += msg.Text
	}
	return h, nil
}

// start turns the form into `vpsctl harden` arguments and runs them as the
// Hardening Task.
func (h hardening) start() (tea.Model, tea.Cmd) {
	var args []string
	for _, f := range h.fields {
		if v := strings.TrimSpace(f.value); v != "" {
			args = append(args, f.flag, v)
		} else if f.on {
			args = append(args, f.flag)
		}
	}
	o, err := harden.ParseFlags(args)
	if err != nil {
		h.status = "ERROR: " + err.Error()
		return h, nil
	}
	h.status = ""
	port := o.Port // the port to log in on at the Verify Gate
	if port == 0 {
		port, _ = h.m.CurrentPort()
	}
	var steps []taskStep
	for _, s := range harden.Steps(o) {
		steps = append(steps, taskStep{s.Name, func(r system.Runner, out io.Writer) error {
			return s.Do(rawKeyMachine(taskMachine(h.m, r), taskTerminal(out)), out, taskGate(out, gateCommand(h.m.Root, port, o.User)))
		}})
	}
	summary := fmt.Sprintf("admin %s · ssh :%d · password auth off · root login off", o.User, port)
	return h, runTask("Hardening", "harden "+strings.Join(args, " "), summary, steps...)
}

func (h hardening) View() tea.View {
	switch {
	case !h.loaded:
		return tea.NewView(titleStyle.Render("Hardening") + "\n\nloading…")
	case h.hst:
		return tea.NewView(h.layout().Render())
	}
	var b strings.Builder
	b.WriteString(titleStyle.Render("Hardening") + "\n\n")
	for i, f := range h.fields {
		cur := "  "
		if i == h.cursor {
			cur = "> "
		}
		v := f.value
		if f.toggle {
			v = "[ ]"
			if f.on {
				v = "[x]"
			}
		} else if i == h.cursor {
			v += "█"
		}
		fmt.Fprintf(&b, "%s%-44s %s\n", cur, f.label, v)
	}
	b.WriteString("\n" + dimStyle.Render("↑/↓ move · space toggle · enter run (with the Verify Gate) · esc back"))
	if h.status != "" {
		b.WriteString("\n\n" + h.status)
	}
	return tea.NewView(b.String())
}
