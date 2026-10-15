package tui

import (
	"fmt"
	"os"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/user"
)

func init() { screens["Users"] = newUsers }

// users lists the Managed Users, read live when opened; the operator's own
// user (SUDO_USER) is marked. It creates key-only users and adds keys to the
// selected one, pasted or generated (private key shown raw via rawKeyMachine
// or written to a mode-600 file).
type users struct {
	m      *harden.Machine
	list   []user.ManagedUser
	err    error
	loaded bool
	cursor int
	ask    usersAsk // the question being typed, if any
	job    string   // status once a running key generation succeeds; "" when none
	status string   // outcome of the last action
}

// usersAsk is a one-line question; enter hands the trimmed answer to do.
type usersAsk struct {
	label, input string
	do           func(u users, answer string) (users, tea.Cmd)
}

type usersMsg struct {
	list   []user.ManagedUser
	err    error
	status string
}

func newUsers(m *harden.Machine) tea.Model { return users{m: m} }

func (u users) Init() tea.Cmd { return u.load("") }

// load re-reads the Managed Users, then shows status.
func (u users) load(status string) tea.Cmd {
	return func() tea.Msg {
		list, err := u.m.ManagedUsers()
		return usersMsg{list, err, status}
	}
}

func (u users) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case usersMsg:
		u.list, u.err, u.loaded, u.status = msg.list, msg.err, true, msg.status
		u.cursor = min(u.cursor, max(len(u.list)-1, 0))
	case gateMsg: // key generation finished (it never stops at the Verify Gate)
		done := u.job
		u.job = ""
		return u, u.load(outcome(done, msg.err))
	case tea.PasteMsg:
		if u.ask.do != nil {
			u.ask.input += msg.Content
		}
	case tea.KeyPressMsg:
		switch {
		case u.ask.do != nil:
			return u.askKey(msg)
		case u.job != "": // stay open for the job's messages
		default:
			return u.key(msg)
		}
	}
	return u, nil
}

func (u users) key(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	sel, ok := u.selected()
	switch msg.String() {
	case "esc":
		return u, Back
	case "up", "k":
		u.cursor = max(u.cursor-1, 0)
	case "down", "j":
		u.cursor = min(u.cursor+1, max(len(u.list)-1, 0))
	case "c":
		u.ask = usersAsk{label: "New user name", do: func(u users, name string) (users, tea.Cmd) {
			return u, u.mutate("users create "+name, "created "+name, func() error { return u.m.CreateUser(name) })
		}}
	case "a":
		if ok {
			u.ask = usersAsk{label: "Public key for " + sel, do: func(u users, key string) (users, tea.Cmd) {
				return u, u.mutate("users add-key "+sel, "added a key to "+sel, func() error { return u.m.AddKey(sel, key) })
			}}
		}
	case "g":
		if ok {
			u.ask = usersAsk{label: "Key file for " + sel + "'s new private key, mode 600 (blank = show on screen)",
				do: func(u users, keyOut string) (users, tea.Cmd) {
					u.job, u.status = "added a generated key to "+sel, ""
					return u, runGated(u.m.Root, "users generate-key "+sel, func(_ func(string) (bool, error), release func() func()) error {
						return rawKeyMachine(u.m, release).GenerateKey(sel, keyOut)
					})
				}}
		}
	}
	return u, nil
}

// askKey edits the answer; enter runs it, esc cancels.
func (u users) askKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		u.ask = usersAsk{}
	case "backspace":
		if r := []rune(u.ask.input); len(r) > 0 {
			u.ask.input = string(r[:len(r)-1])
		}
	case "enter":
		ask := u.ask
		u.ask = usersAsk{}
		return ask.do(u, strings.TrimSpace(ask.input))
	default:
		u.ask.input += msg.Text
	}
	return u, nil
}

// selected is the name of the Managed User under the cursor.
func (u users) selected() (string, bool) {
	if u.cursor < len(u.list) {
		return u.list[u.cursor].Name, true
	}
	return "", false
}

// mutate runs do through logMutation as action, then re-reads the users.
func (u users) mutate(action, done string, do func() error) tea.Cmd {
	return func() tea.Msg {
		return u.load(outcome(done, logMutation(u.m.Root, action, do)))()
	}
}

// outcome is done, or the error when err is set.
func outcome(done string, err error) string {
	if err != nil {
		return "ERROR: " + err.Error()
	}
	return done
}

func (u users) View() tea.View {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Users") + "\n\n")
	switch {
	case !u.loaded:
		b.WriteString("loading…")
	case u.err != nil:
		b.WriteString("users unreadable: " + u.err.Error())
	case len(u.list) == 0:
		b.WriteString("no Managed Users")
	default:
		fmt.Fprintf(&b, "  %-12s %-5s %-5s %s", "NAME", "SUDO", "KEYS", "LOCKED")
		me := os.Getenv("SUDO_USER")
		for i, mu := range u.list {
			cur := "  "
			if i == u.cursor {
				cur = "> "
			}
			name := mu.Name
			if name == me {
				name += " (you)"
			}
			fmt.Fprintf(&b, "\n%s%-12s %-5s %-5d %s", cur, name, yesNo(mu.Sudo), mu.Keys, yesNo(mu.Locked))
		}
	}
	b.WriteString("\n\n")
	switch {
	case u.ask.do != nil:
		b.WriteString(u.ask.label + ": " + u.ask.input + "█\n" + dimStyle.Render("enter ok · esc cancel"))
	case u.job != "":
		b.WriteString("generating key…")
	default:
		b.WriteString(dimStyle.Render("c create · a add key (paste) · g generate key"))
	}
	if u.status != "" {
		b.WriteString("\n\n" + u.status)
	}
	return tea.NewView(b.String())
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
