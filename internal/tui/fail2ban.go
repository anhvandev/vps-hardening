package tui

import (
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/harden"
)

func init() { screens["fail2ban"] = newFail2ban }

// fail2ban lists jails and banned IPs, unbans an IP and adds an IP or CIDR to
// the ignore list in vpsctl's jail drop-in.
type fail2ban struct {
	m     *harden.Machine
	state *f2bState // nil while loading
}

// f2bState is one read of the live fail2ban.
type f2bState struct {
	down string // "not installed" or "not running"; "" when running
}

func newFail2ban(m *harden.Machine) tea.Model { return fail2ban{m: m} }

func (f fail2ban) Init() tea.Cmd { return func() tea.Msg { return readF2b(f.m) } }

func readF2b(m *harden.Machine) *f2bState {
	res, err := m.R.Run("fail2ban-client", "status")
	switch {
	case err != nil:
		return &f2bState{down: "not installed"}
	case res.Code != 0:
		return &f2bState{down: "not running"}
	}
	return &f2bState{}
}

func (f fail2ban) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case *f2bState:
		f.state = msg
	case tea.KeyPressMsg:
		if msg.String() == "esc" {
			return f, Back
		}
	}
	return f, nil
}

func (f fail2ban) View() tea.View {
	var b strings.Builder
	b.WriteString(titleStyle.Render("fail2ban") + "\n\n")
	switch {
	case f.state == nil:
		b.WriteString("loading…")
	case f.state.down != "":
		b.WriteString("fail2ban is " + f.state.down)
	}
	return tea.NewView(b.String())
}
