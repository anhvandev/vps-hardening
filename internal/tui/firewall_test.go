package tui

import (
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/anhvandev/vpsctl/internal/actionlog"
	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

// ssOut is `ss -Hltunp`: sshd and postgres on tcp, DNS on udp 53.
var ssOut = system.Result{Stdout: "udp   UNCONN 0      0      127.0.0.53%lo:53      0.0.0.0:*    users:((\"systemd-resolve\",pid=601,fd=13))\n" +
	"tcp   LISTEN 0      4096   0.0.0.0:22         0.0.0.0:*    users:((\"sshd\",pid=812,fd=3))\n" +
	"tcp   LISTEN 0      4096      [::]:22            [::]:*    users:((\"sshd\",pid=812,fd=4))\n" +
	"tcp   LISTEN 0      244    127.0.0.1:5432     0.0.0.0:*    users:((\"postgres\",pid=990,fd=7))\n"}

// firewallScreenOn is the loaded Firewall screen on h (SSH on port 22) at
// the size it gets in a 120×40 terminal.
func firewallScreenOn(h *testHost) tea.Model {
	h.fake.Results["sshd -T"] = system.Result{Stdout: "port 22\n"}
	h.write("/etc/ssh/ssh_host_ed25519_key", "k")
	s := screens["Firewall"](harden.NewMachine(h.fake, h.host, h.root, io.Discard))
	s, _ = s.Update(tea.WindowSizeMsg{Width: 92, Height: 36})
	s, _ = s.Update(s.Init()())
	return s
}

// firewallView opens the Firewall screen on h and returns its loaded view.
func firewallView(h *testHost) string {
	return ansi.Strip(firewallScreenOn(h).View().Content)
}

// wantRule checks the table line whose first column is want[0], split on
// spaces (borders and the selection mark left out).
func wantRule(t *testing.T, view string, want ...string) {
	t.Helper()
	for _, line := range strings.Split(view, "\n") {
		if f := strings.Fields(strings.NewReplacer("│", " ", "▌", " ").Replace(line)); len(f) > 0 && f[0] == want[0] {
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
	h.fake.Results["ss -Hltunp"] = ssOut
	v := firewallView(h)
	wantAll(t, v, "ufw · active · 3 rules", "PORT", "LISTENING", "NOTE")
	wantRule(t, v, "22", "tcp", "any", "●", "sshd", "SSH", "◆")
	wantRule(t, v, "80", "tcp", "any", "·", "nothing")
	wantRule(t, v, "5432", "tcp", "10.0.0.0/8", "●", "postgres")
}

// Ranges count any listener inside them; tcp and udp are matched separately.
func TestFirewallListsFirewalldRulesWithListeners(t *testing.T) {
	h := debianHost(t)
	h.host = system.Host{DistroID: "rocky", Version: "9.4", Family: "rhel"}
	h.fake.Results = map[string]system.Result{
		"firewall-cmd --state":                       {Stdout: "running\n"},
		"firewall-cmd --permanent --list-ports":      {Stdout: "5000-5500/tcp 50-60/udp 53/tcp 8080/tcp\n"},
		"firewall-cmd --permanent --list-services":   {Stdout: "ssh dhcpv6-client\n"},
		"firewall-cmd --permanent --list-rich-rules": {Stdout: `rule family="ipv4" source address="10.0.0.0/8" port port="5432" protocol="tcp" accept` + "\n"},
		"ss -Hltunp": ssOut,
	}
	v := firewallView(h)
	wantAll(t, v, "firewalld · active")
	wantRule(t, v, "5000-5500", "tcp", "any", "●", "postgres")
	wantRule(t, v, "50-60", "udp", "any", "●", "systemd-resolve")
	wantRule(t, v, "53", "tcp", "any", "·", "nothing")
	wantRule(t, v, "8080", "tcp", "any", "·", "nothing")
	wantRule(t, v, "22", "tcp", "any", "●", "sshd", "SSH", "◆")
	wantRule(t, v, "5432", "tcp", "10.0.0.0/8", "●", "postgres")
}

// A ufw rule without a protocol is backed by a listener on either.
func TestFirewallProtolessUfwRule(t *testing.T) {
	h := debianHost(t)
	h.fake.Results["ufw show added"] = system.Result{Stdout: "ufw allow 53\nufw allow 1000:2000\n"}
	h.fake.Results["ss -Hltunp"] = ssOut
	v := firewallView(h)
	wantRule(t, v, "53", "any", "any", "●", "systemd-resolve")
	wantRule(t, v, "1000-2000", "any", "any", "·", "nothing")
}

// A missing or stopped firewall, or a missing ss, is a state, not a failure.
func TestFirewallStates(t *testing.T) {
	h := debianHost(t)
	h.fake.Results["ufw status"] = system.Result{Stdout: "Status: inactive\n"}
	v := firewallView(h) // no ss scripted
	wantAll(t, v, "ufw · inactive")
	wantRule(t, v, "80", "tcp", "any", "·", "unknown")

	delete(h.fake.Results, "ufw status")
	wantAll(t, firewallView(h), "ufw · not installed")

	h.host = system.Host{DistroID: "rocky", Version: "9.4", Family: "rhel"}
	h.fake.Results = map[string]system.Result{
		"firewall-cmd --state":                  {Code: 252, Stdout: "not running\n"},
		"firewall-cmd --permanent --list-ports": {Code: 252, Stderr: "FirewallD is not running\n"},
	}
	v = firewallView(h)
	wantAll(t, v, "firewalld · inactive")
	if strings.Contains(v, "unreadable") || strings.Contains(v, "LISTENING") {
		t.Errorf("stopped firewalld shows an error or table:\n%s", v)
	}
}

// The table renders inside the shell, and esc hands focus back to the menu.
func TestFirewallScreenFlow(t *testing.T) {
	h := debianHost(t)
	h.fake.Results["ss -Hltunp"] = ssOut
	tm := start(h)
	waitFor(t, tm, "RAM")
	tm.Type(menuTo("Firewall"))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "LISTENING")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape})
	waitFor(t, tm, "q quit")
	v := quitView(t, tm)
	wantAll(t, v, "ufw · active", "10.0.0.0/8")
}

// openFirewall starts the TUI on h and focuses the loaded Firewall screen.
func openFirewall(t *testing.T, h *testHost) *teatest.TestModel {
	t.Helper()
	return openFirewallOn(t, h, h.fake)
}

// openFirewallOn is openFirewall with commands going through r (wrapping h.fake).
func openFirewallOn(t *testing.T, h *testHost, r system.Runner) *teatest.TestModel {
	t.Helper()
	h.fake.Results["ss -Hltunp"] = ssOut
	h.fake.Results["sshd -T"] = system.Result{Stdout: "port 22\n"}
	h.write("/etc/ssh/ssh_host_ed25519_key", "k")
	h.write("/run/.keep", "") // the lock lives under /run
	tm := teatest.NewTestModel(t, New(harden.NewMachine(r, h.host, h.root, io.Discard), time.Now()), teatest.WithInitialTermSize(120, 40))
	waitFor(t, tm, "RAM")
	tm.Type(menuTo("Firewall"))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "LISTENING")
	return tm
}

// closeFirewall leaves the Firewall screen and quits, returning the last frame.
func closeFirewall(t *testing.T, tm *teatest.TestModel) string {
	t.Helper()
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape})
	waitFor(t, tm, "q quit")
	return quitView(t, tm)
}

// press types keys into screen s, running each resulting command (and the
// commands its messages return) to completion.
func press(s tea.Model, keys string) tea.Model {
	for _, c := range keys {
		var cmd tea.Cmd
		s, cmd = s.Update(tea.KeyPressMsg{Code: c, Text: string(c)})
		for cmd != nil {
			s, cmd = s.Update(cmd())
		}
	}
	return s
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
	ctrlCView(t, tm)
	if got := mutations(h); !slices.Equal(got, []string{"ufw allow from 10.0.0.0/8 to any port 6000:6100 proto udp"}) {
		t.Errorf("ran %q", got)
	}
	if log := actionLog(t, h); strings.Count(log, "\n") != 1 || !strings.Contains(log, "firewall open 6000-6100/udp from 10.0.0.0/8: ok") {
		t.Errorf("action log:\n%s", log)
	}
}

// rulesDrop lists only the rules in after once dropped is set: another
// session changed them meanwhile.
type rulesDrop struct {
	*system.Fake
	after   string
	dropped atomic.Bool
}

func (r *rulesDrop) Run(name string, args ...string) (system.Result, error) {
	if r.dropped.Load() && strings.Join(append([]string{name}, args...), " ") == "ufw show added" {
		return system.Result{Stdout: r.after}, nil
	}
	return r.Fake.Run(name, args...)
}

// The Lockout Guard decides again under the lock: when the second SSH rule
// is gone by then, the Task fails at its first step, the Failed card naming
// the step and the reason.
func TestFirewallRefusesRemovingSSHPortRule(t *testing.T) {
	h := debianHost(t)
	h.fake.Results["ufw show added"] = system.Result{Stdout: "ufw allow 22/tcp\nufw allow 22\n"}
	r := &rulesDrop{Fake: h.fake, after: "ufw allow 22/tcp\n"}
	tm := openFirewallOn(t, h, r)
	r.dropped.Store(true)
	tm.Type("dy") // first row: 22/tcp, removable as loaded (22 stays open)
	waitFor(t, tm, `step 1/2 "Lockout Guard check": refused: SSH port 22`)
	wantAll(t, ctrlCView(t, tm), "Task: Remove rule 22/tcp", "Failed", "would no longer be", "open to anywhere")
	if got := mutations(h); len(got) != 0 {
		t.Errorf("ran %q", got)
	}
	if log := actionLog(t, h); strings.Count(log, "\n") != 1 || !strings.Contains(log, "firewall remove 22/tcp: failed: refused: SSH port 22 would no longer be open to anywhere") {
		t.Errorf("action log:\n%s", log)
	}
	wantAll(t, oneOutput(t, h), `step 1/2 "Lockout Guard check" failed: refused`)
}

// Removing a rule deletes exactly that rule: 80/tcp, 443/tcp and the
// source-limited rule are each removed alone.
func TestFirewallRemovesOnlySelectedRule(t *testing.T) {
	for _, c := range []struct{ keys, done, cmd string }{
		{"jjdy", "removed 443/tcp", "ufw delete allow 443/tcp"},
		{"jjjdy", "removed 5432/tcp from 10.0.0.0/8", "ufw delete allow from 10.0.0.0/8 to any port 5432 proto tcp"},
		{"jdy", "removed 80/tcp", "ufw delete allow 80/tcp"},
	} {
		h := debianHost(t)
		h.fake.Results["ufw show added"] = system.Result{Stdout: "ufw allow 22/tcp\nufw allow 80/tcp\nufw allow 443/tcp\n" +
			"ufw allow from 10.0.0.0/8 to any port 5432 proto tcp\n"}
		h.fake.Results[c.cmd] = system.Result{}
		tm := openFirewall(t, h)
		tm.Type(c.keys)
		waitFor(t, tm, c.done)
		ctrlCView(t, tm)
		if got := mutations(h); !slices.Equal(got, []string{c.cmd}) {
			t.Errorf("ran %q, want %q", got, c.cmd)
		}
		if log := actionLog(t, h); strings.Count(log, ": ok\n") != 1 {
			t.Errorf("action log:\n%s", log)
		}
	}
}

// Bad input is refused inline, before any lock, command or log line.
func TestFirewallOpenValidatesInput(t *testing.T) {
	h := debianHost(t)
	s := firewallScreenOn(h)
	for in, want := range map[string]string{
		"0/tcp":                   "invalid port range",
		"65536/tcp":               "invalid port range",
		"200-100/tcp":             "invalid port range",
		"80/icmp":                 "protocol must be tcp or udp",
		"80":                      "protocol must be tcp or udp",
		"http/tcp":                "want PORT[-END]/tcp|udp",
		"80/tcp from nowhere":     "invalid source",
		"80/tcp from 10.0.0.0/33": "invalid source",
	} {
		s = press(s, "a"+in)
		var cmd tea.Cmd
		s, cmd = s.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
		if v := ansi.Strip(s.View().Content); cmd != nil || !strings.Contains(v, want) {
			t.Errorf("%q: want inline %q, no action:\n%s", in, want, v)
		}
		s, _ = s.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	}
	if got := mutations(h); len(got) != 0 {
		t.Errorf("ran %q", got)
	}
	if log := actionLog(t, h); log != "" {
		t.Errorf("action log:\n%s", log)
	}
}

// While another session holds the lock, a mutation is refused with its
// holder and nothing runs; the rules are still listed.
func TestFirewallLockBusy(t *testing.T) {
	h := debianHost(t)
	h.write("/run/.keep", "")
	lk, err := actionlog.Lock(filepath.Join(h.root, actionlog.LockPath))
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Close()
	tm := openFirewall(t, h)
	tm.Type("jdy")
	waitFor(t, tm, "refused: locked by ")
	v := closeFirewall(t, tm)
	wantAll(t, v, "(pid ", "80", "5432")
	if got := mutations(h); len(got) != 0 {
		t.Errorf("ran %q", got)
	}
	if log := actionLog(t, h); log != "" {
		t.Errorf("action log:\n%s", log)
	}
}

// A mutation the firewall rejects is shown inline and logged as failed.
func TestFirewallFailedOpenIsLogged(t *testing.T) {
	h := debianHost(t)
	h.fake.Results["ufw allow 8080/tcp"] = system.Result{Code: 1, Stderr: "ERROR: boom"}
	tm := openFirewall(t, h)
	tm.Type("a8080/tcp")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, `step 1/1 "Allow 8080/tcp": ufw allow 8080/tcp: exit 1: ERROR: boom`)
	ctrlCView(t, tm)
	if log := actionLog(t, h); strings.Count(log, "\n") != 1 || !strings.Contains(log, "firewall open 8080/tcp: failed: ") {
		t.Errorf("action log:\n%s", log)
	}
}

// Cells of the Firewall screen in the 120×40 test terminal: the screen's
// top-left is (27, 1); its rows start at screen line 3, its buttons are on
// line 12 with [ Remove ] from column 18; the confirm's buttons on line 3.
const (
	fwX, fwY       = 27, 1
	firstRowY      = fwY + 3
	buttonsY       = fwY + 12
	removeX        = fwX + 18
	confirmYesX    = fwX + 40
	confirmButtonY = fwY + 3
)

// The Lockout Guard protects the SSH rule: it is marked ◆, [ Remove ] is
// greyed out with the reason in the detail box, and neither d nor a click on
// it asks, runs or logs anything.
func TestFirewallSSHRuleRemoveDisabled(t *testing.T) {
	h := debianHost(t)
	tm := openFirewall(t, h) // first row: 22/tcp, selected
	tm.Type("d")
	tm.Send(click(removeX, buttonsY))
	v := ctrlCView(t, tm)
	wantAll(t, v, "SSH ◆", "[ Remove ]", "─ 22/tcp", "Lockout Guard: SSH port 22 would no longer be open to",
		"a open port · d remove · r refresh · esc back · ? help")
	if strings.Contains(v, "Remove rule") || strings.Contains(v, "Task:") {
		t.Errorf("disabled Remove asked or ran:\n%s", v)
	}
	if got := mutations(h); len(got) != 0 {
		t.Errorf("ran %q", got)
	}
	if log := actionLog(t, h); log != "" {
		t.Errorf("action log:\n%s", log)
	}
}

// Clicking a row selects it, [ Remove ] asks Yes/No, and [ Yes ] removes
// exactly that rule.
func TestFirewallClickRowRemoveYes(t *testing.T) {
	h := debianHost(t)
	h.fake.Results["ufw delete allow 80/tcp"] = system.Result{}
	tm := openFirewall(t, h)
	tm.Send(click(fwX+5, firstRowY+1)) // 80/tcp
	tm.Send(click(removeX+2, buttonsY))
	waitFor(t, tm, "Remove rule 80/tcp?")
	tm.Send(click(confirmYesX, confirmButtonY))
	waitFor(t, tm, "removed 80/tcp")
	ctrlCView(t, tm)
	if got := mutations(h); !slices.Equal(got, []string{"ufw delete allow 80/tcp"}) {
		t.Errorf("ran %q", got)
	}
}

// The wheel scrolls a table longer than the screen; the selection stays on
// a shown row.
func TestFirewallWheelScrolls(t *testing.T) {
	h := debianHost(t)
	var rules strings.Builder
	for p := 1001; p <= 1040; p++ {
		fmt.Fprintf(&rules, "ufw allow %d/tcp\n", p)
	}
	h.fake.Results["ufw show added"] = system.Result{Stdout: rules.String()}
	h.fake.Results["ss -Hltunp"] = ssOut
	h.write("/run/.keep", "")
	tm := start(h)
	waitFor(t, tm, "1033/tcp") // the Overview lists them: RAM falls off the screen
	tm.Type(menuTo("Firewall"))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "LISTENING")
	tm.Send(tea.MouseWheelMsg{X: fwX + 5, Y: firstRowY + 2, Button: tea.MouseWheelDown})
	v := ctrlCView(t, tm)
	wantAll(t, v, "─ 1004/tcp", "1025")
	if strings.Contains(v, "1001") || strings.Contains(v, "1026") {
		t.Errorf("want rows 1004–1025 shown:\n%s", v)
	}
}

// / filters the rules by text; d then acts on the filtered selection.
func TestFirewallFilter(t *testing.T) {
	h := debianHost(t)
	tm := openFirewall(t, h)
	tm.Type("/10.0")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	tm.Type("d")
	v := ctrlCView(t, tm)
	wantAll(t, v, "/ 10.0", "Remove rule 5432/tcp from 10.0.0.0/8?")
	if lineHas(v, "│ 80 ") || lineHas(v, "22", "SSH ◆") {
		t.Errorf("filtered-out rules shown:\n%s", v)
	}
}

// ? and m reach the shell from the Firewall screen, but are typed into a
// text field that has focus.
func TestFirewallGlobalKeysExceptWhileTyping(t *testing.T) {
	h := debianHost(t)
	tm := openFirewall(t, h)
	tm.Type("?")
	waitFor(t, tm, "any key closes this help")
	tm.Type("x")
	tm.Type("a?m")
	waitFor(t, tm, "enter ok · esc cancel")
	v := ctrlCView(t, tm)
	wantAll(t, v, "Port: ?m")
	if strings.Contains(v, "closes this help") {
		t.Errorf("? opened help while typing:\n%s", v)
	}
}
