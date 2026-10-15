package tui

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
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
	m       *harden.Machine
	state   *f2bState // nil while loading
	cursor  int       // index into state.bans
	editing bool      // typing an ignore-list entry
	input   string
}

// jailDropIn is vpsctl's jail drop-in, first written by `vpsctl harden`.
const jailDropIn = "/etc/fail2ban/jail.d/00-vpsctl.local"

var ignoreRe = regexp.MustCompile(`(?m)^ignoreip\s*=(.*)$`)

// f2bState is one read of the live fail2ban, plus the result of the last action.
type f2bState struct {
	down   string // "not installed" or "not running"; "" when running
	jails  []string
	bans   []ban    // in jail order
	ignore []string // ignoreip in the drop-in
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
	b, _ := os.ReadFile(filepath.Join(m.Root, jailDropIn))
	if sub := ignoreRe.FindSubmatch(b); sub != nil {
		s.ignore = strings.Fields(string(sub[1]))
	}
	return s
}

// addIgnore appends entry to the drop-in's first ignoreip line, keeping
// existing entries; without one it adds a [DEFAULT] ignoreip for all jails.
func addIgnore(root, entry string) error {
	p := filepath.Join(root, jailDropIn)
	b, err := os.ReadFile(p)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	s := string(b)
	if loc := ignoreRe.FindStringSubmatchIndex(s); loc != nil {
		list := strings.Fields(s[loc[2]:loc[3]])
		if !slices.Contains(list, entry) {
			list = append(list, entry)
		}
		s = s[:loc[0]] + "ignoreip = " + strings.Join(list, " ") + s[loc[1]:]
	} else {
		s = "[DEFAULT]\nignoreip = " + entry + "\n\n" + s
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(s), 0o644)
}

// validIgnore reports whether s is an IP address or CIDR.
func validIgnore(s string) bool {
	_, errA := netip.ParseAddr(s)
	_, errP := netip.ParsePrefix(s)
	return errA == nil || errP == nil
}

// sessionIP is the client IP of the operator's SSH session: SSH_CONNECTION
// from the nearest ancestor that has it (sudo drops it from our own env).
// "" when not found, e.g. on the provider console.
func sessionIP(root string) string {
	pid := strconv.Itoa(os.Getpid())
	for range 32 { // bounded walk up the process tree
		env, _ := os.ReadFile(filepath.Join(root, "/proc", pid, "environ"))
		for _, kv := range strings.Split(string(env), "\x00") {
			if v, ok := strings.CutPrefix(kv, "SSH_CONNECTION="); ok {
				if f := strings.Fields(v); len(f) > 0 {
					return f[0]
				}
			}
		}
		stat, err := os.ReadFile(filepath.Join(root, "/proc", pid, "stat"))
		i := strings.LastIndexByte(string(stat), ')')
		if err != nil || i < 0 {
			return ""
		}
		f := strings.Fields(string(stat[i+1:])) // state, ppid, ...
		if len(f) < 2 || f[1] == "0" || f[1] == "1" {
			return ""
		}
		pid = f[1]
	}
	return ""
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
		if f.editing {
			return f.editKey(msg)
		}
		switch msg.String() {
		case "i":
			if f.state != nil && f.state.down == "" {
				f.editing, f.input = true, sessionIP(f.m.Root)
			}
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

// editKey handles keys while typing an ignore-list entry.
func (f fail2ban) editKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		f.editing = false
	case "backspace":
		if r := []rune(f.input); len(r) > 0 {
			f.input = string(r[:len(r)-1])
		}
	case "enter":
		entry := strings.TrimSpace(f.input)
		if !validIgnore(entry) {
			f.state.status = fmt.Sprintf("ERROR: %q is not an IP or CIDR", entry)
			return f, nil
		}
		f.editing = false
		return f, f.mutate("fail2ban ignore "+entry, "added "+entry+" to the ignore list", func() error {
			if err := addIgnore(f.m.Root, entry); err != nil {
				return err
			}
			return checkedRun(f.m.R, "fail2ban-client", "reload")
		})
	default:
		f.input += msg.Text
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
	ignore := "none"
	if len(f.state.ignore) > 0 {
		ignore = strings.Join(f.state.ignore, " ")
	}
	b.WriteString("\nIgnore list: " + ignore + "\n")
	if f.editing {
		b.WriteString("\nAdd IP or CIDR: " + f.input + "█\n" + dimStyle.Render("enter save · esc cancel") + "\n")
	} else {
		b.WriteString("\n" + dimStyle.Render("u unban · i add to ignore list") + "\n")
	}
	if f.state.status != "" {
		b.WriteString("\n" + f.state.status)
	}
	return tea.NewView(b.String())
}
