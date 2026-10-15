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
	"github.com/charmbracelet/x/ansi"

	"github.com/anhvandev/vpsctl/internal/guard"
	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/sshd"
	"github.com/anhvandev/vpsctl/internal/system"
	"github.com/anhvandev/vpsctl/internal/user"
)

func init() { screens["SSH"] = newSSH }

var warnStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("3"))

// sshScreen shows the effective sshd config (Match overrides flagged) and the
// active SSH sessions, the operator's own marked. It offers no switch that
// could weaken Hardening. p changes the port as a Task through
// harden.ChangeSSH, with the Verify Gate in the Task panel; it is disabled
// until SSH is hardened.
type sshScreen struct {
	m        *harden.Machine
	info     *sshInfo // nil while loading
	table    table    // active sessions
	changing bool     // the change form is up
	form     form
	w, h     int
}

type sshInfo struct {
	settings    []sshd.Setting
	settingsErr error
	sessions    []sshd.Session
	sessionsErr error
	users       []user.ManagedUser
	listening   []int // tcp Listening Ports, nil if ss failed
	hardened    bool  // Stage B live
}

func newSSH(m *harden.Machine) tea.Model {
	return sshScreen{m: m, table: newTable("USER", "FROM", "SINCE")}
}

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
		info.users, info.settingsErr = users, err
		info.sessions, info.sessionsErr = s.m.SSH.Sessions()
		info.listening = tcpListening(s.m.R)
		info.hardened = s.m.SSH.StageBLive()
		return &info
	}
}

// tcpListening is every tcp Listening Port, nil if ss failed.
func tcpListening(r system.Runner) []int {
	var ports []int
	for _, l := range listeningPorts(r) {
		if l.proto == "tcp" {
			ports = append(ports, l.port)
		}
	}
	return ports
}

// port is the current SSH port from the effective config, 0 when unknown.
func (s sshScreen) port() int {
	for _, st := range s.info.settings {
		if st.Key == "port" {
			p, _ := strconv.Atoi(strings.Split(st.Value, ",")[0])
			return p
		}
	}
	return 0
}

func (s sshScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		s.w, s.h = msg.Width, msg.Height
		s.table.height = max(s.h-17, 3) // room for the config, header, buttons or form
		s.table.setRows(s.table.rows)
		return s, nil
	case *sshInfo:
		s.info = msg
		var rows [][]string
		for _, se := range msg.sessions {
			name := se.User
			if se.Own {
				name += " (you)"
			}
			rows = append(rows, []string{name, se.From, se.Since})
		}
		s.table.setRows(rows)
		return s, nil
	case taskDoneMsg:
		return s, s.Init()
	case tea.MouseClickMsg:
		if m := mouse(s.layout(), msg); m != nil {
			return s.Update(m)
		}
		return s, nil
	}
	if s.changing {
		return s.formUpdate(msg)
	}
	if t, ok := s.table.update(msg); ok {
		s.table = t
		return s, nil
	}
	k, ok := msg.(tea.KeyPressMsg)
	if !ok || disabled(s.buttons(), k.String()) {
		return s, nil
	}
	switch k.String() {
	case "esc":
		return s, Back
	case "p":
		s.changing, s.form = true, newForm("Change the SSH port", "New port")
		s.form.inputs[0].Placeholder = "1-65535; the Verify Gate follows"
		if system.SessionUser() == "" { // root on the console: who logs in at the gate?
			s.form = newForm("Change the SSH port", "New port", "Login user")
			s.form.inputs[1].Placeholder = "the Admin User you will log in as at the Verify Gate"
			if i := slices.IndexFunc(s.info.users, user.ManagedUser.Usable); i >= 0 {
				s.form.inputs[1].SetValue(s.info.users[i].Name)
			}
		}
	case "r":
		return s, s.Init()
	}
	return s, nil
}

// formUpdate edits the change form; enter validates (the Lockout Guard on
// the loaded facts included), then starts the change.
func (s sshScreen) formUpdate(msg tea.Msg) (tea.Model, tea.Cmd) {
	f, ev := s.form.update(msg)
	s.form, s.changing = f, ev == editing
	if ev != submitted {
		return s, nil
	}
	s.changing = true // until it validates
	port, err := strconv.Atoi(strings.TrimSpace(s.form.value(0)))
	login := system.SessionUser()
	if len(s.form.inputs) > 1 {
		login = strings.TrimSpace(s.form.value(1))
	}
	refusal := guard.Check(guard.Facts{SSHPort: s.port(), Listening: s.info.listening}, guard.ChangeSSHPort{Port: port})
	switch {
	case err != nil || port < 1 || port > 65535:
		s.form.err = "port must be 1-65535"
	case refusal != nil:
		s.form.err = refusal.Error()
	case len(s.form.inputs) > 1 && !slices.ContainsFunc(s.info.users, func(u user.ManagedUser) bool { return u.Name == login }):
		s.form.err = "not a Managed User: enter the Admin User to log in as"
	default:
		s.changing = false
		return s, s.changePort(port, login)
	}
	return s, nil
}

// changePort moves SSH to port as a Task: the two-stage change with the
// Verify Gate for login in between, unless the Lockout Guard refuses on
// facts read under the lock.
func (s sshScreen) changePort(port int, login string) tea.Cmd {
	var cur int // the port before, read under the lock
	return runTask(fmt.Sprintf("Change SSH port to %d", port), fmt.Sprintf("ssh port %d", port), fmt.Sprintf("SSH moved to port %d", port),
		taskStep{"Lockout Guard check", func(r system.Runner, _ io.Writer) error {
			var err error
			if cur, err = taskMachine(s.m, r).CurrentPort(); err != nil {
				return err
			}
			return guard.Check(guard.Facts{SSHPort: cur, Listening: tcpListening(r)}, guard.ChangeSSHPort{Port: port})
		}},
		taskStep{fmt.Sprintf("Move SSH to port %d (Verify Gate)", port), func(r system.Runner, out io.Writer) error {
			_, err := harden.ChangeSSH(harden.Options{User: login, Port: port}, taskMachine(s.m, r), out,
				taskGate(out, gateCommand(s.m.Root, port, login)))
			if errors.Is(err, harden.ErrStopped) {
				return fmt.Errorf("%w: SSH stays on port %d", err, cur)
			}
			return err
		}})
}

func (s sshScreen) typing() bool { return s.changing || s.table.typing() }

func (s sshScreen) keys() string {
	switch {
	case s.changing:
		return s.form.keys()
	case s.table.typing():
		return s.table.keys()
	}
	return s.table.keys() + " · " + keyHelp(s.buttons()) + " · esc back"
}

func (s sshScreen) buttons() []button {
	change := button{"p", "Change port", ""}
	if s.info == nil || !s.info.hardened {
		// ChangeSSH would apply Stage B alone, without the rest of Hardening.
		change.why = "SSH is not hardened yet: run the Hardening wizard (it sets the port too)"
	}
	return []button{change, {"r", "Refresh", ""}}
}

// layout is the screen: header, effective config, sessions table, buttons
// (or the change form).
func (s sshScreen) layout() *lipgloss.Compositor {
	if s.info == nil {
		return stack(titleStyle.Render("SSH"), "", "loading…")
	}
	title := titleStyle.Render("SSH")
	summary := fmt.Sprintf("port %d · %d sessions", s.port(), len(s.info.sessions))
	blocks := []any{title + strings.Repeat(" ", max(s.w-ansi.StringWidth(title)-ansi.StringWidth(summary), 1)) + summary,
		"Effective config (sshd -T)"}
	if s.info.settingsErr != nil {
		blocks = append(blocks, "  unreadable: "+s.info.settingsErr.Error())
	}
	for _, st := range s.info.settings {
		line := fmt.Sprintf("  %-32s %s", st.Key, st.Value)
		if len(st.Overrides) > 0 {
			var o []string
			for _, ov := range st.Overrides {
				o = append(o, ov.User+"="+ov.Value)
			}
			line += "  " + warnStyle.Render(glyph("⚠")+" Match: "+strings.Join(o, ", "))
		}
		blocks = append(blocks, line)
	}
	blocks = append(blocks, "", "Active sessions")
	if s.info.sessionsErr != nil {
		blocks = append(blocks, "  unreadable: "+s.info.sessionsErr.Error())
	} else {
		blocks = append(blocks, s.table.layer(s.w))
	}
	if s.changing {
		return stack(append(blocks, "", s.form.view())...)
	}
	bs := s.buttons()
	blocks = append(blocks, buttonRow(bs...))
	if bs[0].why != "" {
		blocks = append(blocks, " "+dimStyle.Render("Change port: "+bs[0].why))
	}
	return stack(blocks...)
}

func (s sshScreen) View() tea.View { return tea.NewView(s.layout().Render()) }
