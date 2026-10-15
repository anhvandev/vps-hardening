package tui

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/anhvandev/vpsctl/internal/guard"
	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/sshd"
	"github.com/anhvandev/vpsctl/internal/system"
	"github.com/anhvandev/vpsctl/internal/user"
)

func init() { screens["SSH"] = newSSH }

var warnStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("3"))

// sshScreen shows the effective sshd config (Match overrides flagged) and the
// active SSH sessions. It offers no switch that could weaken Hardening.
// p changes the port through harden.ChangeSSH and the Verify Gate dialog.
type sshScreen struct {
	m       *harden.Machine
	info    *sshInfo // nil while loading
	editing bool     // a prompt is up: the new port, or the login user if askFor is set
	input   string
	askFor  int         // new port waiting for the login-user answer (no SUDO_USER)
	port    int         // port being changed to; 0 = no change running
	user    string      // login user to try at the Verify Gate
	gate    *verifyGate // non-nil while the change waits at the Verify Gate
	status  string      // outcome of the last change, or an input error
}

type sshInfo struct {
	settings    []sshd.Setting
	settingsErr error
	sessions    []sshd.Session
	sessionsErr error
}

func newSSH(m *harden.Machine) tea.Model { return sshScreen{m: m} }

func (s sshScreen) busy() bool { return s.port != 0 }

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
	case gateMsg:
		if msg.ask != nil {
			g := newVerifyGate(msg, s.m.Root, s.port, s.user)
			s.gate = &g
			return s, nil
		}
		s.status = fmt.Sprintf("SSH port changed to %d", s.port)
		if msg.err != nil {
			s.status = "ERROR: " + msg.err.Error()
		}
		s.port = 0
		return s, s.Init()
	case tea.KeyPressMsg:
		switch {
		case s.gate != nil:
			g, cmd := s.gate.Update(msg)
			if s.gate = &g; cmd != nil {
				s.gate = nil
			}
			return s, cmd
		case s.editing:
			return s.promptKey(msg)
		case s.port != 0: // a change is running: stay open for its messages
		case msg.String() == "esc":
			return s, Back
		case msg.String() == "p" && !s.m.SSH.StageBLive():
			// ChangeSSH would apply Stage B alone, without the rest of Hardening.
			s.status = "SSH is not hardened yet: run the Hardening wizard (it sets the port too)"
		case msg.String() == "p":
			s.editing, s.input, s.status = true, "", ""
		}
	}
	return s, nil
}

// promptKey edits the prompt; enter validates, then starts the change. Without
// SUDO_USER (root on the console) it first asks the login user to try at the
// Verify Gate, suggesting the first usable Admin User.
func (s sshScreen) promptKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		s.editing, s.askFor, s.status = false, 0, ""
	case "backspace":
		if r := []rune(s.input); len(r) > 0 {
			s.input = string(r[:len(r)-1])
		}
	case "enter":
		if s.askFor != 0 {
			name := strings.TrimSpace(s.input)
			users, _ := s.m.ManagedUsers()
			if !slices.ContainsFunc(users, func(u user.ManagedUser) bool { return u.Name == name }) {
				s.status = "not a Managed User: enter the Admin User to log in as"
				return s, nil
			}
			return s.start(s.askFor, name)
		}
		port, err := strconv.Atoi(strings.TrimSpace(s.input))
		switch {
		case err != nil || port < 1 || port > 65535:
			s.status = "port must be 1-65535"
		case system.SessionUser() == "":
			s.askFor, s.input, s.status = port, "", ""
			users, _ := s.m.ManagedUsers()
			if i := slices.IndexFunc(users, user.ManagedUser.Usable); i >= 0 {
				s.input = users[i].Name
			}
		default:
			return s.start(port, system.SessionUser())
		}
	default:
		s.input += msg.Text
	}
	return s, nil
}

// start closes the prompt and changes the port, user logging in at the gate.
func (s sshScreen) start(port int, user string) (tea.Model, tea.Cmd) {
	s.editing, s.askFor, s.status, s.port, s.user = false, 0, "", port, user
	return s, s.changePort(port, user)
}

// changePort moves SSH to port with the two-stage change, the Verify Gate
// for user in between, unless the Lockout Guard refuses on facts read under
// the lock.
func (s sshScreen) changePort(port int, user string) tea.Cmd {
	return runGated(s.m.Root, fmt.Sprintf("ssh port %d", port), func(ask func(string) (bool, error), _ func() func()) error {
		cur, err := s.m.CurrentPort()
		if err != nil {
			return err
		}
		var listening []int // nil when ss failed
		for _, l := range listeners(s.m.R) {
			if l.proto == "tcp" {
				listening = append(listening, l.port)
			}
		}
		if err := guard.Check(guard.Facts{SSHPort: cur, Listening: listening}, guard.ChangeSSHPort{Port: port}); err != nil {
			return err
		}
		_, err = harden.ChangeSSH(harden.Options{User: user, Port: port}, s.m, io.Discard, ask)
		if errors.Is(err, harden.ErrStopped) {
			return fmt.Errorf("%w: SSH stays on port %d", err, cur)
		}
		return err
	})
}

func (s sshScreen) View() tea.View {
	if s.gate != nil {
		return tea.NewView(s.gate.View())
	}
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
	b.WriteString("\n\n")
	switch {
	case s.editing && s.askFor != 0:
		b.WriteString("No SUDO_USER: which Admin User will you log in as?\nLogin user for the Verify Gate: " + s.input + "█\n" +
			dimStyle.Render("enter change (with the Verify Gate) · esc cancel"))
	case s.editing:
		b.WriteString("New SSH port: " + s.input + "█\n" + dimStyle.Render("enter change (with the Verify Gate) · esc cancel"))
	case s.port != 0:
		fmt.Fprintf(&b, "changing the SSH port to %d…", s.port)
	default:
		b.WriteString(dimStyle.Render("p change the SSH port"))
	}
	if s.status != "" {
		b.WriteString("\n\n" + s.status)
	}
	return tea.NewView(b.String())
}
