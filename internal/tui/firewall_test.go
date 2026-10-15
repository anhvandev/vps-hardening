package tui

import (
	"io"
	"slices"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

// ssOut is `ss -Hltun`: sshd and postgres on tcp, DNS on udp 53.
var ssOut = system.Result{Stdout: "udp   UNCONN 0      0      127.0.0.53%lo:53      0.0.0.0:*\n" +
	"tcp   LISTEN 0      4096   0.0.0.0:22         0.0.0.0:*\n" +
	"tcp   LISTEN 0      4096      [::]:22            [::]:*\n" +
	"tcp   LISTEN 0      244    127.0.0.1:5432     0.0.0.0:*\n"}

// firewallView opens the Firewall screen on h and returns its loaded view.
func firewallView(h *testHost) string {
	s := screens["Firewall"](harden.NewMachine(h.fake, h.host, h.root, io.Discard))
	s, _ = s.Update(s.Init()())
	return ansi.Strip(s.View().Content)
}

// wantRule checks the table line whose first column is want[0], split on spaces.
func wantRule(t *testing.T, view string, want ...string) {
	t.Helper()
	for _, line := range strings.Split(view, "\n") {
		if f := strings.Fields(line); len(f) > 0 && f[0] == want[0] {
			if !slices.Equal(f, want) {
				t.Errorf("rule %s = %q, want %q\n%s", want[0], f, want, view)
			}
			return
		}
	}
	t.Errorf("no rule %s in:\n%s", want[0], view)
}

func TestFirewallListsUfwRulesWithListeners(t *testing.T) {
	h := debianHost(t)
	h.fake.Results["ss -Hltun"] = ssOut
	v := firewallView(h)
	wantAll(t, v, "ufw active")
	wantRule(t, v, "22", "tcp", "anywhere", "yes")
	wantRule(t, v, "80", "tcp", "anywhere", "no")
	wantRule(t, v, "5432", "tcp", "10.0.0.0/8", "yes")
}

// The table renders inside the shell, and esc hands focus back to the menu.
func TestFirewallScreenFlow(t *testing.T) {
	h := debianHost(t)
	h.fake.Results["ss -Hltun"] = ssOut
	tm := start(h)
	waitFor(t, tm, "RAM")
	tm.Type("jj")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "Listening")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape})
	waitFor(t, tm, "q quit")
	v := quitView(t, tm)
	wantAll(t, v, "ufw active", "10.0.0.0/8")
}
