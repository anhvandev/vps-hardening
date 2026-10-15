package tui

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/anhvandev/vpsctl/internal/actionlog"
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

// Ranges count any listener inside them; tcp and udp are matched separately.
func TestFirewallListsFirewalldRulesWithListeners(t *testing.T) {
	h := debianHost(t)
	h.host = system.Host{DistroID: "rocky", Version: "9.4", Family: "rhel"}
	h.fake.Results = map[string]system.Result{
		"firewall-cmd --state":                     {Stdout: "running\n"},
		"firewall-cmd --permanent --list-ports":    {Stdout: "5000-5500/tcp 50-60/udp 53/tcp 8080/tcp\n"},
		"firewall-cmd --permanent --list-services": {Stdout: "ssh dhcpv6-client\n"},
		"firewall-cmd --permanent --list-rich-rules": {Stdout: `rule family="ipv4" source address="10.0.0.0/8" port port="5432" protocol="tcp" accept` + "\n"},
		"ss -Hltun": ssOut,
	}
	v := firewallView(h)
	wantAll(t, v, "firewalld active")
	wantRule(t, v, "5000-5500", "tcp", "anywhere", "yes")
	wantRule(t, v, "50-60", "udp", "anywhere", "yes")
	wantRule(t, v, "53", "tcp", "anywhere", "no")
	wantRule(t, v, "8080", "tcp", "anywhere", "no")
	wantRule(t, v, "22", "tcp", "anywhere", "yes")
	wantRule(t, v, "5432", "tcp", "10.0.0.0/8", "yes")
}

// A ufw rule without a protocol is backed by a listener on either.
func TestFirewallProtolessUfwRule(t *testing.T) {
	h := debianHost(t)
	h.fake.Results["ufw show added"] = system.Result{Stdout: "ufw allow 53\nufw allow 1000:2000\n"}
	h.fake.Results["ss -Hltun"] = ssOut
	v := firewallView(h)
	wantRule(t, v, "53", "any", "anywhere", "yes")
	wantRule(t, v, "1000-2000", "any", "anywhere", "no")
}

// A missing or stopped firewall, or a missing ss, is a state, not a failure.
func TestFirewallStates(t *testing.T) {
	h := debianHost(t)
	h.fake.Results["ufw status"] = system.Result{Stdout: "Status: inactive\n"}
	v := firewallView(h) // no ss scripted
	wantAll(t, v, "ufw inactive")
	wantRule(t, v, "80", "tcp", "anywhere", "unknown")

	delete(h.fake.Results, "ufw status")
	wantAll(t, firewallView(h), "ufw not installed")

	h.host = system.Host{DistroID: "rocky", Version: "9.4", Family: "rhel"}
	h.fake.Results = map[string]system.Result{
		"firewall-cmd --state":                  {Code: 252, Stdout: "not running\n"},
		"firewall-cmd --permanent --list-ports": {Code: 252, Stderr: "FirewallD is not running\n"},
	}
	v = firewallView(h)
	wantAll(t, v, "firewalld inactive")
	if strings.Contains(v, "unreadable") || strings.Contains(v, "Listening") {
		t.Errorf("stopped firewalld shows an error or table:\n%s", v)
	}
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

// openFirewall starts the TUI on h and focuses the loaded Firewall screen.
func openFirewall(t *testing.T, h *testHost) *teatest.TestModel {
	t.Helper()
	h.fake.Results["ss -Hltun"] = ssOut
	h.fake.Results["sshd -T"] = system.Result{Stdout: "port 22\n"}
	h.write("/etc/ssh/ssh_host_ed25519_key", "k")
	tm := start(h)
	waitFor(t, tm, "RAM")
	tm.Type("jj")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "Listening")
	return tm
}

// closeFirewall leaves the Firewall screen and quits, returning the last frame.
func closeFirewall(t *testing.T, tm *teatest.TestModel) string {
	t.Helper()
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape})
	waitFor(t, tm, "q quit")
	return quitView(t, tm)
}

// actionLog is the action log written under h's root ("" if none).
func actionLog(h *testHost) string {
	b, _ := os.ReadFile(filepath.Join(h.root, actionlog.LogPath))
	return string(b)
}

// mutations is every firewall-changing command h ran.
func mutations(h *testHost) []string {
	var cmds []string
	for _, c := range h.fake.Calls {
		if strings.HasPrefix(c, "ufw allow") || strings.HasPrefix(c, "ufw delete") {
			cmds = append(cmds, c)
		}
	}
	return cmds
}

func TestFirewallOpenPort(t *testing.T) {
	h := debianHost(t)
	h.fake.Results["ufw allow from 10.0.0.0/8 to any port 6000:6100 proto udp"] = system.Result{}
	tm := openFirewall(t, h)
	tm.Type("a6000-6100/udp from 10.0.0.0/8")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "opened 6000-6100/udp from 10.0.0.0/8")
	closeFirewall(t, tm)
	if got := mutations(h); !slices.Equal(got, []string{"ufw allow from 10.0.0.0/8 to any port 6000:6100 proto udp"}) {
		t.Errorf("ran %q", got)
	}
	if log := actionLog(h); strings.Count(log, "\n") != 1 || !strings.Contains(log, "firewall open 6000-6100/udp from 10.0.0.0/8: ok") {
		t.Errorf("action log:\n%s", log)
	}
}
