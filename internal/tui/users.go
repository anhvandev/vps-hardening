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
// user (SUDO_USER) is marked.
type users struct {
	m      *harden.Machine
	list   []user.ManagedUser
	err    error
	loaded bool
}

type usersMsg struct {
	list []user.ManagedUser
	err  error
}

func newUsers(m *harden.Machine) tea.Model { return users{m: m} }

func (u users) Init() tea.Cmd {
	return func() tea.Msg {
		list, err := u.m.ManagedUsers()
		return usersMsg{list, err}
	}
}

func (u users) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case usersMsg:
		u.list, u.err, u.loaded = msg.list, msg.err, true
	case tea.KeyPressMsg:
		if msg.String() == "esc" {
			return u, Back
		}
	}
	return u, nil
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
		fmt.Fprintf(&b, "%-12s %-5s %-5s %s", "NAME", "SUDO", "KEYS", "LOCKED")
		me := os.Getenv("SUDO_USER")
		for _, mu := range u.list {
			name := mu.Name
			if name == me {
				name += " (you)"
			}
			fmt.Fprintf(&b, "\n%-12s %-5s %-5d %s", name, yesNo(mu.Sudo), mu.Keys, yesNo(mu.Locked))
		}
	}
	return tea.NewView(b.String())
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
