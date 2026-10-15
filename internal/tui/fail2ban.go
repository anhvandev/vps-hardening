package tui

import (
	"fmt"
	"path/filepath"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/actionlog"
	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

func init() { screens["fail2ban"] = newFail2ban }

// fail2ban lists jails and banned IPs, unbans an IP and adds an IP or CIDR to
// the ignore list in vpsctl's jail drop-in.
type fail2ban struct {
	m      *harden.Machine
	state  *f2bState // nil while loading
	cursor int       // index into state.bans
}

// f2bState is one read of the live fail2ban, plus the result of the last action.
type f2bState struct {
	down   string // "not installed" or "not running"; "" when running
	jails  []string
	bans   []ban // in jail order
	status string
}

type ban struct{ jail, ip string }

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
	s := &f2bState{}
	if list, ok := f2bField(res.Stdout, "Jail list:"); ok {
		for _, j := range strings.Split(list, ",") {
			if j = strings.TrimSpace(j); j != "" {
				s.jails = append(s.jails, j)
			}
		}
	}
	for _, j := range s.jails {
		res, err := m.R.Run("fail2ban-client", "status", j)
		if err != nil || res.Code != 0 {
			continue
		}
		ips, _ := f2bField(res.Stdout, "Banned IP list:")
		for _, ip := range strings.Fields(ips) {
			s.bans = append(s.bans, ban{j, ip})
		}
	}
	return s
}

// f2bField is the value after label in fail2ban-client's tree output.
func f2bField(out, label string) (string, bool) {
	for _, line := range strings.Split(out, "\n") {
		if _, v, ok := strings.Cut(line, label); ok {
			return strings.TrimSpace(v), true
		}
	}
	return "", false
}

func (f fail2ban) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case *f2bState:
		f.state = msg
		f.cursor = min(f.cursor, max(len(msg.bans)-1, 0))
	case tea.KeyPressMsg:
		switch msg.String() {
		case "esc":
			return f, Back
		case "up", "k":
			f.cursor = max(f.cursor-1, 0)
		case "down", "j":
			if f.state != nil {
				f.cursor = min(f.cursor+1, max(len(f.state.bans)-1, 0))
			}
		case "u":
			if f.state != nil && f.cursor < len(f.state.bans) {
				b := f.state.bans[f.cursor]
				return f, f.mutate("fail2ban unban "+b.ip+" "+b.jail, "unbanned "+b.ip+" from "+b.jail, func() error {
					return checkedRun(f.m.R, "fail2ban-client", "set", b.jail, "unbanip", b.ip)
				})
			}
		}
	}
	return f, nil
}

// mutate runs do under the global lock, logs it as action, then re-reads fail2ban.
func (f fail2ban) mutate(action, done string, do func() error) tea.Cmd {
	return func() tea.Msg {
		status := done
		if err := logMutation(f.m.Root, action, do); err != nil {
			status = "ERROR: " + err.Error()
		}
		s := readF2b(f.m)
		s.status = status
		return s
	}
}

// logMutation takes the global lock under root, runs do and appends one
// action-log line. A busy lock returns its holder and runs nothing.
func logMutation(root, action string, do func() error) error {
	lk, err := actionlog.Lock(filepath.Join(root, actionlog.LockPath))
	if err != nil {
		return err
	}
	defer lk.Close()
	err = do()
	result := "ok"
	if err != nil {
		result = "failed: " + err.Error()
	}
	actionlog.Append(filepath.Join(root, actionlog.LogPath), action, result) // failures to log are ignored
	return err
}

// checkedRun is r.Run with a non-zero exit turned into an error.
func checkedRun(r system.Runner, name string, args ...string) error {
	res, err := r.Run(name, args...)
	if err == nil && res.Code != 0 {
		err = fmt.Errorf("%s %s: exit %d: %s", name, strings.Join(args, " "), res.Code, strings.TrimSpace(res.Stderr))
	}
	return err
}

func (f fail2ban) View() tea.View {
	var b strings.Builder
	b.WriteString(titleStyle.Render("fail2ban") + "\n\n")
	switch {
	case f.state == nil:
		b.WriteString("loading…")
		return tea.NewView(b.String())
	case f.state.down != "":
		b.WriteString("fail2ban is " + f.state.down)
		return tea.NewView(b.String())
	}
	if len(f.state.jails) == 0 {
		b.WriteString("no jails\n")
	}
	i := 0
	for _, j := range f.state.jails {
		b.WriteString(titleStyle.Render(j) + "\n")
		n := 0
		for ; i < len(f.state.bans) && f.state.bans[i].jail == j; i++ {
			cur := "  "
			if i == f.cursor {
				cur = "> "
			}
			b.WriteString(cur + f.state.bans[i].ip + "\n")
			n++
		}
		if n == 0 {
			b.WriteString(dimStyle.Render("  no bans") + "\n")
		}
	}
	b.WriteString("\n" + dimStyle.Render("u unban") + "\n")
	if f.state.status != "" {
		b.WriteString("\n" + f.state.status)
	}
	return tea.NewView(b.String())
}
