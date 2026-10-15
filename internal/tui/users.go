package tui

import (
	"fmt"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/guard"
	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
	"github.com/anhvandev/vpsctl/internal/user"
)

func init() { screens["Users"] = newUsers }

// users lists the Managed Users, read live when opened; the operator's own
// user (SUDO_USER) is marked. It creates key-only users and adds keys to the
// selected one, pasted or generated (private key shown raw via rawKeyMachine
// or written to a mode-600 file). It removes one key, toggles sudo and lock,
// and deletes users, each past the Lockout Guard.
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
// oneLine refuses a multi-line paste outright.
type usersAsk struct {
	label, input string
	oneLine      bool
	do           func(u users, answer string) (users, tea.Cmd)
}

type usersMsg struct {
	list   []user.ManagedUser
	err    error
	status string
}

func newUsers(m *harden.Machine) tea.Model { return users{m: m} }

func (u users) Init() tea.Cmd { return u.load("") }

func (u users) busy() bool { return u.job != "" }

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
		switch {
		case u.ask.do == nil:
		case u.ask.oneLine && strings.ContainsAny(strings.TrimSpace(msg.Content), "\r\n"):
			u.status = "ERROR: paste one line only"
		default:
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
		u.ask = usersAsk{label: "New user name", oneLine: true, do: func(u users, name string) (users, tea.Cmd) {
			if !user.ValidName(name) { // the input may be a pasted secret: keep it out of the log
				return u, u.mutate("users create", "", func() error { return user.ErrInvalidName })
			}
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
	case "x":
		if ok {
			return u.askRemoveKey(sel), nil
		}
	case "s":
		switch {
		case ok && u.list[u.cursor].Sudo:
			return u, u.guarded("revoke-sudo", sel, "revoked sudo from "+sel, func() error { return u.m.RevokeSudo(sel) })
		case ok:
			return u, u.guarded("grant-sudo", sel, "granted sudo to "+sel, func() error { return u.m.GrantSudo(sel) })
		}
	case "l":
		switch {
		case ok && u.list[u.cursor].Locked:
			return u, u.guarded("unlock", sel, "unlocked "+sel, func() error { return u.m.Unlock(sel) })
		case ok:
			return u, u.guarded("lock", sel, "locked "+sel, func() error { return u.m.Lock(sel) })
		}
	case "d":
		if ok {
			u.ask = usersAsk{label: "Delete " + sel + ": also remove the home directory? y/N (blank keeps it)",
				do: func(u users, answer string) (users, tea.Cmd) {
					rm := strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes")
					done := "deleted " + sel + ", home kept"
					if rm {
						done = "deleted " + sel + " and its home"
					}
					return u, u.guarded("delete", sel, done, func() error { return u.m.DeleteUser(sel, rm) })
				}}
		}
	}
	return u, nil
}

// askRemoveKey asks which of sel's keys to remove, by number.
func (u users) askRemoveKey(sel string) users {
	keys, err := u.m.Keys(sel)
	switch {
	case err != nil:
		u.status = "ERROR: " + err.Error()
		return u
	case len(keys) == 0:
		u.status = sel + " has no keys"
		return u
	}
	label := "Keys of " + sel + ":"
	for i, k := range keys {
		if r := []rune(k); len(r) > 64 { // the blob's middle tells keys apart least
			k = string(r[:20]) + "…" + string(r[len(r)-40:])
		}
		label += fmt.Sprintf("\n  %d  %s", i+1, k)
	}
	u.ask = usersAsk{label: label + "\nRemove key number", do: func(u users, answer string) (users, tea.Cmd) {
		n, err := strconv.Atoi(answer)
		if err != nil || n < 1 || n > len(keys) {
			u.status = fmt.Sprintf("ERROR: want a key number from 1 to %d", len(keys))
			return u, nil
		}
		return u, u.guarded("remove-key", sel, "removed a key from "+sel, func() error { return u.m.RemoveKey(sel, keys[n-1]) })
	}}
	return u
}

// guarded runs do through mutate as "users VERB NAME" unless the Lockout
// Guard refuses, deciding on the session user and the users read under the lock.
func (u users) guarded(verb, name, done string, do func() error) tea.Cmd {
	return u.mutate("users "+verb+" "+name, done, func() error {
		list, err := u.m.ManagedUsers()
		if err != nil {
			return err
		}
		if err := guard.Check(guard.Facts{SessionUser: system.SessionUser(), Users: list}, guard.UserAction{User: name, Verb: verb}); err != nil {
			return err
		}
		return do()
	})
}

// askKey edits the answer; enter runs it, esc cancels.
func (u users) askKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		u.ask = usersAsk{}
	case "backspace":
		u.ask.input = dropLast(u.ask.input)
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
		me := system.SessionUser()
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
		b.WriteString(dimStyle.Render("c create · a add key (paste) · g generate key · x remove key · s sudo on/off · l lock/unlock · d delete"))
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
