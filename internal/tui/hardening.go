package tui

import (
	"errors"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/harden"
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

// hardening is the Hardening wizard: the inputs of `vpsctl harden`, checked
// by the same harden.ParseFlags, then harden.Run with the Verify Gate dialog
// and the private key shown raw outside the TUI (rawKeyMachine) or written
// to the key file.
type hardening struct {
	m       *harden.Machine
	fields  []hardenField
	cursor  int
	running bool
	gate    *verifyGate // non-nil while Hardening waits at the Verify Gate
	status  string      // outcome of the last run, or an input error
}

func newHardening(m *harden.Machine) tea.Model {
	return hardening{m: m, fields: []hardenField{
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

func (h hardening) Init() tea.Cmd { return nil }

func (h hardening) busy() bool { return h.running }

func (h hardening) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case gateMsg:
		if msg.ask != nil {
			port, _ := h.m.CurrentPort() // Stage A is live: the port to log in on
			g := newVerifyGate(msg, h.m.Root, port, strings.TrimSpace(h.fields[0].value))
			h.gate = &g
			return h, nil
		}
		h.running = false
		switch {
		case msg.err == nil:
			h.status = "Hardening complete: password and root login are off. Log under " + harden.LogDir
		case errors.Is(msg.err, harden.ErrStopped):
			h.status = "Stopped at the Verify Gate: password auth still enabled, nothing locked; re-run when the new login works"
		default:
			h.status = "ERROR: " + msg.err.Error()
		}
	case tea.KeyPressMsg:
		switch {
		case h.gate != nil:
			g, cmd := h.gate.Update(msg)
			if h.gate = &g; cmd != nil {
				h.gate = nil
			}
			return h, cmd
		case h.running: // stay open for the job's messages
		default:
			return h.key(msg)
		}
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
		if r := []rune(f.value); len(r) > 0 {
			f.value = string(r[:len(r)-1])
		}
	default:
		f.value += msg.Text
	}
	return h, nil
}

// start turns the form into `vpsctl harden` arguments and runs them.
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
	h.running, h.status = true, ""
	return h, runGated(h.m.Root, "harden "+strings.Join(args, " "), func(ask func(string) (bool, error), release func() func()) error {
		logf, err := harden.OpenLog(h.m.Root)
		if err != nil {
			return err
		}
		defer logf.Close()
		return harden.Run(o, rawKeyMachine(h.m, release), logf, ask)
	})
}

func (h hardening) View() tea.View {
	if h.gate != nil {
		return tea.NewView(h.gate.View())
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
	b.WriteString("\n")
	if h.running {
		b.WriteString("hardening…")
	} else {
		b.WriteString(dimStyle.Render("↑/↓ move · space toggle · enter run (with the Verify Gate) · esc back"))
	}
	if h.status != "" {
		b.WriteString("\n\n" + h.status)
	}
	return tea.NewView(b.String())
}
