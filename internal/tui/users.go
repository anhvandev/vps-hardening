package tui

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/anhvandev/vpsctl/internal/guard"
	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/logins"
	"github.com/anhvandev/vpsctl/internal/system"
	"github.com/anhvandev/vpsctl/internal/user"
)

func init() { screens["Users"] = newUsers }

// users lists the Managed Users, read live when opened; the operator's own
// user (SUDO_USER) is marked (you). Every change is a Task: create a
// key-only user, add a pasted key or generate a pair (private key shown raw
// outside the alternate screen via rawKeyMachine, or written to a mode-600
// file), remove one key, sudo on/off, lock/unlock (each after a Yes/No) and
// delete (typing the name; home kept unless switched). Actions the Lockout
// Guard refuses are disabled with the reason in the detail box (rows marked
// ◆); the guard checks again under the lock.
type users struct {
	m        *harden.Machine
	list     []user.ManagedUser
	authKeys [][]string           // each user's key lines; nil when unreadable
	last     map[string]time.Time // newest SSH login per user in the last 7 days
	err      error
	loaded   bool
	table    table
	form     form
	onForm   func(u users) (users, tea.Cmd) // the form is up; called on enter
	asking   bool                           // the confirm is up
	ask      confirm
	yes      func(u users) tea.Cmd // what the confirm runs
	rmHome   bool                  // the delete confirm also removes the home
	w, h     int
}

type usersMsg struct {
	list []user.ManagedUser
	keys [][]string
	last map[string]time.Time
	err  error
}

func newUsers(m *harden.Machine) tea.Model {
	return users{m: m, table: newTable("USER", "SUDO", "KEYS", "STATE", "LAST LOGIN", "")}
}

// Init re-reads the Managed Users and their keys.
func (u users) Init() tea.Cmd {
	return func() tea.Msg {
		list, err := u.m.ManagedUsers()
		var keys [][]string
		for _, mu := range list {
			k, _ := u.m.Keys(mu.Name)
			keys = append(keys, k)
		}
		last := map[string]time.Time{}
		ls, _ := logins.Read(u.m.R, u.m.Root, logins.Week, time.Now()) // unreadable: every LAST LOGIN "—"
		for _, l := range ls {
			if l.OK && l.Time.After(last[l.User]) {
				last[l.User] = l.Time
			}
		}
		return usersMsg{list, keys, last, err}
	}
}

func (u users) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		u.w, u.h = msg.Width, msg.Height
		u.table.height = max(u.h-16, 3) // room for the header, detail box and buttons or form
		u.table.setRows(u.table.rows)
		return u, nil
	case usersMsg:
		u.list, u.authKeys, u.last, u.err, u.loaded = msg.list, msg.keys, msg.last, msg.err, true
		u.table.setRows(u.rows())
		return u, nil
	case taskDoneMsg:
		return u, u.Init()
	case tea.MouseClickMsg:
		if m := mouse(u.layout(), msg); m != nil {
			return u.Update(m)
		}
		return u, nil
	}
	switch {
	case u.onForm != nil:
		f, ev := u.form.update(msg)
		u.form = f
		switch ev {
		case cancelled:
			u.onForm = nil
		case submitted:
			return u.onForm(u)
		}
		return u, nil
	case u.asking:
		if k, ok := msg.(tea.KeyPressMsg); ok && k.String() == "tab" && u.ask.name != "" { // delete: keep or remove the home
			u.rmHome = !u.rmHome
			u.ask.title = u.deleteTitle(u.ask.name)
			return u, nil
		}
		c, ev := u.ask.update(msg)
		u.ask, u.asking = c, ev == editing
		if ev == submitted {
			return u, u.yes(u)
		}
		return u, nil
	}
	if t, ok := u.table.update(msg); ok {
		u.table = t
		return u, nil
	}
	k, ok := msg.(tea.KeyPressMsg)
	if !ok || disabled(u.buttons(), k.String()) {
		return u, nil
	}
	i := u.table.selected()
	switch k.String() {
	case "esc":
		return u, Back
	case "r":
		return u, u.Init()
	case "a":
		u.form, u.onForm = newForm("New user (key-only, no sudo)", "Name"), createUser
	case "i":
		name := u.list[i].Name
		u.form = newForm("Add a key to "+name, "Public key (blank = generate a pair)", "Key file (blank = show once on screen)")
		u.onForm = func(u users) (users, tea.Cmd) { return u.addKey(name) }
	case "x":
		name, keys := u.list[i].Name, u.authKeys[i]
		u.form = newForm("Remove a key of "+name, "Key number (as listed above)")
		u.onForm = func(u users) (users, tea.Cmd) { return u.removeKey(name, keys) }
	case "s", "l":
		name := u.list[i].Name
		verb, _ := userAction(k.String(), u.list[i])
		do := userVerbs[verb]
		u.asking, u.ask = true, newConfirm(fmt.Sprintf(do.task, name)+"?")
		u.yes = func(u users) tea.Cmd {
			return u.guarded(verb, name, fmt.Sprintf(do.task, name), fmt.Sprintf(do.done, name), func(m *harden.Machine) error { return do.run(m, name) })
		}
	case "d":
		name := u.list[i].Name
		u.rmHome = false
		u.asking, u.ask = true, newDangerous(u.deleteTitle(name), "Delete", name)
		u.yes = func(u users) tea.Cmd {
			done := "deleted " + name + ", home kept"
			if u.rmHome {
				done = "deleted " + name + " and its home"
			}
			rm := u.rmHome
			return u.guarded("delete", name, "Delete user "+name, done, func(m *harden.Machine) error { return m.DeleteUser(name, rm) })
		}
	}
	return u, nil
}

// userVerbs are the Yes/No user actions: Task name and Done summary (%s is
// the user) and what they run.
var userVerbs = map[string]struct {
	task, done string
	run        func(m *harden.Machine, name string) error
}{
	"grant-sudo":  {"Grant sudo to %s", "granted sudo to %s", (*harden.Machine).GrantSudo},
	"revoke-sudo": {"Revoke sudo from %s", "revoked sudo from %s", (*harden.Machine).RevokeSudo},
	"lock":        {"Lock %s", "locked %s", (*harden.Machine).Lock},
	"unlock":      {"Unlock %s", "unlocked %s", (*harden.Machine).Unlock},
}

// userAction is the Lockout Guard verb and button label of the guarded
// button key (x s l d) for mu.
func userAction(key string, mu user.ManagedUser) (verb, label string) {
	switch {
	case key == "x":
		return "remove-key", "Remove key"
	case key == "s" && mu.NoPasswd:
		return "revoke-sudo", "Sudo off"
	case key == "s":
		return "grant-sudo", "Sudo on"
	case key == "l" && mu.Locked:
		return "unlock", "Unlock"
	case key == "l":
		return "lock", "Lock"
	}
	return "delete", "Delete"
}

// deleteTitle is the delete confirm's title, saying what happens to the home.
func (u users) deleteTitle(name string) string {
	home := "/home/" + name
	for _, mu := range u.list {
		if mu.Name == name {
			home = mu.Home
		}
	}
	if u.rmHome {
		return "Delete user " + name + " · home " + home + ": delete (tab: keep)"
	}
	return "Delete user " + name + " · home " + home + ": keep (tab: delete)"
}

// createUser validates the new user form, then creates the user. An invalid
// name may be a pasted secret: it is refused here, never run or recorded.
func createUser(u users) (users, tea.Cmd) {
	name := strings.TrimSpace(u.form.value(0))
	if !user.ValidName(name) {
		u.form.err = user.ErrInvalidName.Error()
		return u, nil
	}
	u.onForm = nil
	return u, runTask("Create user "+name, "users create "+name, "created "+name,
		taskStep{"Create " + name, func(r system.Runner, _ io.Writer) error { return taskMachine(u.m, r).CreateUser(name) }})
}

// addKey installs the pasted public key, or generates a pair when none is
// pasted. Key text never reaches a Task's output: AddKey's errors don't echo it.
func (u users) addKey(name string) (users, tea.Cmd) {
	key, keyOut := strings.TrimSpace(u.form.value(0)), strings.TrimSpace(u.form.value(1))
	u.onForm = nil
	if key != "" {
		return u, runTask("Add a key to "+name, "users add-key "+name, "added a key to "+name,
			taskStep{"Install the key", func(r system.Runner, _ io.Writer) error { return taskMachine(u.m, r).AddKey(name, key) }})
	}
	return u, runTask("Generate a key for "+name, "users generate-key "+name, "added a generated key to "+name,
		taskStep{"Generate, show and install the key", func(r system.Runner, out io.Writer) error {
			return rawKeyMachine(taskMachine(u.m, r), taskTerminal(out)).GenerateKey(name, keyOut)
		}})
}

// removeKey asks to remove the key numbered in the form from name's keys.
func (u users) removeKey(name string, keys []string) (users, tea.Cmd) {
	n, err := strconv.Atoi(strings.TrimSpace(u.form.value(0)))
	if err != nil || n < 1 || n > len(keys) {
		u.form.err = fmt.Sprintf("want a key number from 1 to %d", len(keys))
		return u, nil
	}
	u.onForm = nil
	u.asking, u.ask = true, newConfirm(fmt.Sprintf("Remove key %d of %s?", n, name))
	u.yes = func(u users) tea.Cmd {
		return u.guarded("remove-key", name, "Remove a key of "+name, "removed a key from "+name,
			func(m *harden.Machine) error { return m.RemoveKey(name, keys[n-1]) })
	}
	return u, nil
}

// guarded runs do as the Task task, recorded as "users VERB NAME", unless the
// Lockout Guard refuses on the session user and the users read under the
// lock (read past the Task's output: ManagedUsers reads shadow).
func (u users) guarded(verb, name, task, done string, do func(m *harden.Machine) error) tea.Cmd {
	return runTask(task, "users "+verb+" "+name, done,
		taskStep{"Lockout Guard check", func(system.Runner, io.Writer) error {
			list, err := u.m.ManagedUsers()
			if err != nil {
				return err
			}
			return guard.Check(guard.Facts{SessionUser: system.SessionUser(), Users: list}, guard.UserAction{User: name, Verb: verb})
		}},
		taskStep{task, func(r system.Runner, _ io.Writer) error { return do(taskMachine(u.m, r)) }})
}

// refusal is why the Lockout Guard would refuse verb on name, "" if it allows it.
func (u users) refusal(name, verb string) string {
	err := guard.Check(guard.Facts{SessionUser: system.SessionUser(), Users: u.list}, guard.UserAction{User: name, Verb: verb})
	if err != nil {
		return strings.TrimPrefix(err.Error(), "refused: ")
	}
	return ""
}

// guardNotes are mu's actions the Lockout Guard refuses, "Label: why" each.
func (u users) guardNotes(mu user.ManagedUser) []string {
	var notes []string
	for _, k := range []string{"x", "s", "l", "d"} {
		verb, label := userAction(k, mu)
		if why := u.refusal(mu.Name, verb); why != "" && (k != "x" || mu.Keys > 0) {
			notes = append(notes, label+": "+why)
		}
	}
	return notes
}

func (u users) buttons() []button {
	i := u.table.selected()
	bs := []button{{"a", "+ New user", ""}, {"i", "+ Add key", ""}}
	for _, k := range []string{"x", "s", "l", "d"} {
		var mu user.ManagedUser
		if i >= 0 {
			mu = u.list[i]
		}
		verb, label := userAction(k, mu)
		b := button{k, label, "no user selected"}
		switch {
		case i < 0:
		case k == "x" && mu.Keys == 0:
			b.why = "no keys"
		default:
			b.why = u.refusal(mu.Name, verb)
		}
		bs = append(bs, b)
	}
	if i < 0 {
		bs[1].why = "no user selected"
	}
	return bs
}

// rows are the table rows, one per Managed User; ◆ marks users the Lockout
// Guard protects from some action.
func (u users) rows() [][]string {
	me := system.SessionUser()
	var rows [][]string
	for _, mu := range u.list {
		name, sudo, state, note := mu.Name, naStyle.Render(glyph("·")), okStyle.Render(glyph("●"))+" active", ""
		if name == me {
			name += " (you)"
		}
		if mu.Sudo {
			sudo = okStyle.Render(glyph("●"))
		}
		if mu.Locked {
			state = warnStyle.Render(glyph("⚠")) + " locked"
		}
		if len(u.guardNotes(mu)) > 0 {
			note = glyph("◆")
		}
		login := "—"
		if t, ok := u.last[mu.Name]; ok {
			login = span(time.Since(t)) + " ago"
		}
		rows = append(rows, []string{name, sudo, strconv.Itoa(mu.Keys), state, login, note})
	}
	return rows
}

// detail lists the selected user's keys, numbered, and the Lockout Guard's
// reasons for its disabled actions.
func (u users) detail(i int) string {
	var ls []string
	switch {
	case u.authKeys[i] == nil && u.list[i].Keys > 0:
		ls = append(ls, "keys: unreadable")
	case len(u.authKeys[i]) == 0:
		ls = append(ls, "keys: none")
	}
	for n, k := range u.authKeys[i] {
		prefix := "keys: "
		if n > 0 {
			prefix = "      "
		}
		ls = append(ls, fmt.Sprintf("%s%d  %s", prefix, n+1, keyLabel(k)))
	}
	for _, note := range u.guardNotes(u.list[i]) {
		ls = append(ls, warnStyle.Render(glyph("◆")+" "+note))
	}
	return strings.Join(ls, "\n")
}

// keyLabel is an authorized_keys line as "ed25519 SHA256:<fingerprint> comment".
func keyLabel(line string) string {
	f := strings.Fields(line)
	for i := 0; i+1 < len(f); i++ { // options may come first
		if strings.HasPrefix(f[i], "ssh-") || strings.HasPrefix(f[i], "ecdsa-") || strings.HasPrefix(f[i], "sk-") {
			fp := "SHA256:?"
			if blob, err := base64.StdEncoding.DecodeString(f[i+1]); err == nil {
				sum := sha256.Sum256(blob)
				fp = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
			}
			return strings.TrimSpace(strings.TrimPrefix(f[i], "ssh-") + " " + fp + " " + strings.Join(f[i+2:], " "))
		}
	}
	return "unrecognised key line"
}

func (u users) typing() bool {
	return u.onForm != nil || u.table.typing() || u.asking && u.ask.typing()
}

func (u users) keys() string {
	switch {
	case u.onForm != nil:
		return u.form.keys()
	case u.asking && u.ask.name != "":
		return u.ask.keys() + " · tab keep/delete home"
	case u.asking:
		return u.ask.keys()
	case u.table.typing():
		return u.table.keys()
	}
	return u.table.keys() + " · " + keyHelp(u.buttons()) + " · r refresh · esc back"
}

// layout is the screen: header, users table, detail box, buttons (or the
// form), and the confirm over them.
func (u users) layout() *lipgloss.Compositor {
	title := titleStyle.Render("Users")
	switch {
	case !u.loaded:
		return stack(title, "", "loading…")
	case u.err != nil:
		return stack(title, "", "users unreadable: "+u.err.Error())
	}
	sudo := 0
	for _, mu := range u.list {
		if mu.Sudo {
			sudo++
		}
	}
	summary := fmt.Sprintf("%d Managed Users · %d with sudo", len(u.list), sudo)
	blocks := []any{title + strings.Repeat(" ", max(u.w-ansi.StringWidth(title)-ansi.StringWidth(summary), 1)) + summary,
		u.table.layer(u.w)}
	if i := u.table.selected(); i >= 0 && u.h >= 26 {
		blocks = append(blocks, detailBox(u.list[i].Name, u.detail(i), u.w, 4))
	}
	if u.onForm != nil {
		blocks = append(blocks, "", u.form.view())
	} else {
		blocks = append(blocks, buttonRow(u.buttons()...))
	}
	c := stack(blocks...)
	if u.asking {
		c.AddLayers(u.ask.layer(u.w))
	}
	return c
}

func (u users) View() tea.View { return tea.NewView(u.layout().Render()) }
