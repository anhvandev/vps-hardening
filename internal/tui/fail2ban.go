package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/fail2ban"
	"github.com/anhvandev/vpsctl/internal/harden"
)

func init() { screens["fail2ban"] = newFail2ban }

// f2bScreen lists jails and banned IPs, unbans an IP and adds an IP or CIDR
// to the ignore list in vpsctl's jail drop-in.
type f2bScreen struct {
	m       *harden.Machine
	state   *f2bState // nil while loading
	cursor  int       // index into state.bans
	editing bool      // typing an ignore-list entry
	input   string
}

// f2bState is one read of the live fail2ban, plus the result of the last action.
type f2bState struct {
	down   string // "not installed" or "not running"; "" when running
	jails  []string
	bans   []fail2ban.Ban // in jail order
	ignore []string       // ignoreip in the drop-in
	status string
}

func newFail2ban(m *harden.Machine) tea.Model { return f2bScreen{m: m} }

func (f f2bScreen) Init() tea.Cmd { return func() tea.Msg { return readF2b(f.m) } }

func readF2b(m *harden.Machine) *f2bState {
	jails, err := fail2ban.Jails(m.R)
	if err != nil {
		return &f2bState{down: err.Error()}
	}
	return &f2bState{jails: jails, bans: fail2ban.Bans(m.R, jails), ignore: fail2ban.Ignore(m.Root)}
}

func (f f2bScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
				return f, f.mutate("fail2ban unban "+b.IP+" "+b.Jail, "unbanned "+b.IP+" from "+b.Jail, func() error {
					return fail2ban.Unban(f.m.R, b)
				})
			}
		}
	}
	return f, nil
}

// editKey handles keys while typing an ignore-list entry.
func (f f2bScreen) editKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		f.editing = false
	case "backspace":
		if r := []rune(f.input); len(r) > 0 {
			f.input = string(r[:len(r)-1])
		}
	case "enter":
		entry := strings.TrimSpace(f.input)
		if !fail2ban.ValidIgnore(entry) {
			f.state.status = fmt.Sprintf("ERROR: %q is not an IP or CIDR", entry)
			return f, nil
		}
		f.editing = false
		return f, f.mutate("fail2ban ignore "+entry, "added "+entry+" to the ignore list", func() error {
			return fail2ban.AddIgnore(f.m.R, f.m.Root, entry)
		})
	default:
		f.input += msg.Text
	}
	return f, nil
}

// mutate runs do under the global lock, logs it as action, then re-reads fail2ban.
func (f f2bScreen) mutate(action, done string, do func() error) tea.Cmd {
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

func (f f2bScreen) View() tea.View {
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
		for ; i < len(f.state.bans) && f.state.bans[i].Jail == j; i++ {
			cur := "  "
			if i == f.cursor {
				cur = "> "
			}
			b.WriteString(cur + f.state.bans[i].IP + "\n")
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
