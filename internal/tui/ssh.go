package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/sshd"
)

func init() { screens["SSH"] = newSSH }

var warnStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("3"))

// sshScreen shows the effective sshd config (Match overrides flagged) and the
// active SSH sessions. It offers no switch that could weaken Hardening.
type sshScreen struct {
	m    *harden.Machine
	info *sshInfo // nil while loading
}

type sshInfo struct {
	settings    []sshd.Setting
	settingsErr error
	sessions    []sshd.Session
	sessionsErr error
}

func newSSH(m *harden.Machine) tea.Model { return sshScreen{m: m} }

func (s sshScreen) Init() tea.Cmd {
	return func() tea.Msg {
		var info sshInfo
		users, err := s.m.ManagedUsers()
		if err == nil {
			var names []string
			for _, u := range users {
				names = append(names, u.Name)
			}
			info.settings, err = s.m.SSH.Settings(names)
		}
		info.settingsErr = err
		info.sessions, info.sessionsErr = s.m.SSH.Sessions()
		return &info
	}
}

func (s sshScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case *sshInfo:
		s.info = msg
	case tea.KeyPressMsg:
		if msg.String() == "esc" {
			return s, Back
		}
	}
	return s, nil
}

func (s sshScreen) View() tea.View {
	if s.info == nil {
		return tea.NewView(titleStyle.Render("SSH") + "\n\nloading…")
	}
	var b strings.Builder
	b.WriteString(titleStyle.Render("SSH") + "\n\nEffective config (sshd -T)")
	if s.info.settingsErr != nil {
		b.WriteString("\n  unreadable: " + s.info.settingsErr.Error())
	}
	for _, st := range s.info.settings {
		fmt.Fprintf(&b, "\n  %-32s %s", st.Key, st.Value)
		if len(st.Overrides) > 0 {
			var o []string
			for _, ov := range st.Overrides {
				o = append(o, ov.User+"="+ov.Value)
			}
			b.WriteString("  " + warnStyle.Render("! Match: "+strings.Join(o, ", ")))
		}
	}
	b.WriteString("\n\nActive sessions")
	switch {
	case s.info.sessionsErr != nil:
		b.WriteString("\n  unreadable: " + s.info.sessionsErr.Error())
	case len(s.info.sessions) == 0:
		b.WriteString("\n  none")
	}
	for _, se := range s.info.sessions {
		fmt.Fprintf(&b, "\n  %-12s %-16s since %s", se.User, se.From, se.Since)
		if se.Own {
			b.WriteString(" (you)")
		}
	}
	return tea.NewView(b.String())
}
