package tui

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

// A Match block re-enabling password auth for a Managed User is flagged; the
// operator's own session is marked.
func TestSSHScreenFlagsMatchOverrideAndOwnSession(t *testing.T) {
	h := debianHost(t)
	global := "port 22\npasswordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\npermitrootlogin no\n"
	for k, v := range map[string]string{
		"getent passwd": "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/bash\n",
		"getent group":  "sudo:x:27:alice\n",
		"getent shadow": "alice:!:19000:0:99999:7:::\nbob:!:19000:0:99999:7:::\n",
		"sshd -T":       global,
		"sshd -T -C user=alice,host=localhost,addr=127.0.0.1": global,
		"sshd -T -C user=bob,host=localhost,addr=127.0.0.1":   strings.Replace(global, "passwordauthentication no", "passwordauthentication yes", 1),
		"loginctl list-sessions --no-legend":                  "5 1000 alice pts/0\n7 1001 bob pts/1\n",
		"loginctl show-session 5 7 -p Id -p Name -p Service -p RemoteHost -p Timestamp": "Id=5\nName=alice\nService=sshd\nRemoteHost=203.0.113.5\nTimestamp=Thu 2026-10-15 09:12:03 UTC\n\n" +
			"Id=7\nName=bob\nService=sshd\nRemoteHost=198.51.100.7\nTimestamp=Thu 2026-10-15 10:00:00 UTC\n",
	} {
		h.fake.Results[k] = system.Result{Stdout: v}
	}
	h.write("/etc/ssh/ssh_host_ed25519_key", "k")
	h.write("/proc/self/cgroup", "0::/user.slice/user-1000.slice/session-5.scope\n")
	tm := start(h)
	waitFor(t, tm, "RAM")
	tm.Type(menuTo("SSH"))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "198.51.100.7")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape})
	waitFor(t, tm, "q quit")
	v := quitView(t, tm)
	wantAll(t, v, "passwordauthentication", "Match: bob=yes", "permitrootlogin",
		"alice", "203.0.113.5", "Thu 2026-10-15 09:12:03 UTC", "(you)", "bob")
	if strings.Count(v, "(you)") != 1 {
		t.Errorf("want exactly one own session:\n%s", v)
	}
}

// sshSim models what an SSH port change touches, on top of h.fake: sshd -T
// reads the port and auth from vpsctl's drop-in, a restart moves the listener there,
// ss reports it, and ufw keeps its rule list.
type sshSim struct {
	*system.Fake
	root      string
	listening int
	ufw       []string // "ufw allow ..." lines
}

func (s *sshSim) Run(name string, args ...string) (system.Result, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	b, _ := os.ReadFile(filepath.Join(s.root, "/etc/ssh/sshd_config.d/00-vpsctl.conf"))
	port := 22
	fmt.Sscanf(strings.SplitN(string(b), "\n", 3)[1], "Port %d", &port)
	switch {
	case strings.HasPrefix(line, "sshd -T"):
		auth := map[bool]string{true: "no", false: "yes"}[strings.Contains(string(b), "PasswordAuthentication no")]
		return system.Result{Stdout: fmt.Sprintf("port %d\npasswordauthentication %s\nkbdinteractiveauthentication no\n"+
			"pubkeyauthentication yes\npermitrootlogin %s\n", port, auth, auth)}, nil
	case line == "sshd -t":
	case line == "systemctl restart ssh":
		s.listening = port
	case line == fmt.Sprintf("ss -ltnH sport = :%d", s.listening):
		return system.Result{Stdout: "LISTEN 0 128 0.0.0.0:" + strconv.Itoa(port) + " 0.0.0.0:*\n"}, nil
	case strings.HasPrefix(line, "ss -ltnH"):
	case strings.HasPrefix(line, "ufw allow "):
		if !slices.Contains(s.ufw, line) {
			s.ufw = append(s.ufw, line)
		}
	case strings.HasPrefix(line, "ufw delete "):
		s.ufw = slices.DeleteFunc(s.ufw, func(r string) bool { return r == "ufw "+strings.TrimPrefix(line, "ufw delete ") })
	case line == "ufw show added":
		return system.Result{Stdout: strings.Join(s.ufw, "\n") + "\n"}, nil
	default:
		return s.Fake.Run(name, args...)
	}
	return system.Result{}, nil
}

// portChangeHost is a hardened host on port 22 (ufw allows 22 and 80) where
// alice, the operator, passes the pre-lock assertions; she came in on 10.0.0.2.
func portChangeHost(t *testing.T) (*testHost, *sshSim) {
	t.Setenv("SUDO_USER", "alice")
	h := debianHost(t)
	uid := strconv.Itoa(os.Getuid())
	for k, v := range map[string]string{
		"getent passwd":              "alice:x:" + uid + ":" + uid + "::/home/alice:/bin/bash\n",
		"getent passwd alice":        "alice:x:" + uid + ":" + uid + "::/home/alice:/bin/bash\n",
		"ufw version":                "ufw 0.36.2\n",
		"sudo -u alice sudo -n true": "",
	} {
		h.fake.Results[k] = system.Result{Stdout: v}
	}
	h.write("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n\nUsePAM yes\n")
	h.write("/etc/ssh/ssh_host_ed25519_key", "k")
	h.write("/run/.keep", "")
	h.write("/home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAA alice\n")
	os.Chmod(filepath.Join(h.root, "/home/alice/.ssh/authorized_keys"), 0o600)
	h.write("/proc/"+strconv.Itoa(os.Getpid())+"/environ", "SSH_CONNECTION=203.0.113.5 50122 10.0.0.2 22\x00")
	return h, &sshSim{Fake: h.fake, root: h.root, listening: 22, ufw: []string{"ufw allow 22/tcp", "ufw allow 80/tcp"}}
}

// changePortOn opens the SSH screen on r, types port into the change form
// and submits it.
func changePortOn(t *testing.T, h *testHost, r system.Runner, port string) *teatest.TestModel {
	t.Helper()
	tm := teatest.NewTestModel(t, New(harden.NewMachine(r, h.host, h.root, io.Discard), time.Now()), teatest.WithInitialTermSize(120, 40))
	waitFor(t, tm, "RAM")
	tm.Type(menuTo("SSH"))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "Active sessions")
	tm.Type("p")
	waitFor(t, tm, "Change the SSH port")
	tm.Type(port)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	return tm
}

// changePort is changePortOn the port-change simulation.
func changePort(t *testing.T, h *testHost, sim *sshSim, port string) *teatest.TestModel {
	t.Helper()
	return changePortOn(t, h, sim, port)
}

// The port change runs as a Task: it stops at the Verify Gate inside the
// Task panel, with the exact login to try, and moves SSH once it works.
func TestSSHPortChangeThroughVerifyGate(t *testing.T) {
	h, sim := portChangeHost(t)
	tm := changePort(t, h, sim, "2222")
	waitFor(t, tm, "ssh -p 2222 alice@10.0.0.2")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyLeft}) // to "Login works"
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "SUMMARY  SSH moved to port 2222")
	v := ctrlCView(t, tm)
	wantAll(t, v, "Task: Change SSH port to 2222", "Done in")
	if sim.listening != 2222 || !slices.Equal(sim.ufw, []string{"ufw allow 80/tcp", "ufw allow 2222/tcp"}) {
		t.Errorf("listening %d, rules %q", sim.listening, sim.ufw)
	}
	if log := actionLog(t, h); strings.Count(log, "\n") != 1 || !strings.HasSuffix(log, "ssh port 2222: ok\n") {
		t.Errorf("Task History:\n%s", log)
	}
	wantAll(t, oneOutput(t, h), "[step 1/2] Lockout Guard check", "Stage A: SSH on port 2222", "$ systemctl restart ssh", "Done: SSH moved to port 2222")
}

// "Stop safely" (the default) restores the pre-change state; the card says
// so and Task History records "stopped".
func TestSSHPortChangeStopSafelyRestores(t *testing.T) {
	h, sim := portChangeHost(t)
	before, _ := os.ReadFile(filepath.Join(h.root, "/etc/ssh/sshd_config.d/00-vpsctl.conf"))
	tm := changePort(t, h, sim, "2222")
	waitFor(t, tm, "[ Stop safely ]")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "restored pre-run SSH state")
	v := ctrlCView(t, tm)
	wantAll(t, v, "Stopped", "SSH stays on port 22")
	after, _ := os.ReadFile(filepath.Join(h.root, "/etc/ssh/sshd_config.d/00-vpsctl.conf"))
	if sim.listening != 22 || !slices.Equal(sim.ufw, []string{"ufw allow 22/tcp", "ufw allow 80/tcp"}) || string(after) != string(before) {
		t.Errorf("listening %d, rules %q, drop-in %q", sim.listening, sim.ufw, after)
	}
	if log := actionLog(t, h); !strings.HasSuffix(log, "ssh port 2222: stopped\n") {
		t.Errorf("Task History:\n%s", log)
	}
}

// On a host that is not hardened (Stage B not live) the port change would
// apply Stage B without the rest of Hardening: Change port is disabled, with
// the reason.
func TestSSHPortChangeDisabledWhenNotHardened(t *testing.T) {
	h, sim := portChangeHost(t)
	h.write("/etc/ssh/sshd_config.d/00-vpsctl.conf", "# Managed by vpsctl - do not edit by hand.\nPort 22\n")
	tm := teatest.NewTestModel(t, New(harden.NewMachine(sim, h.host, h.root, io.Discard), time.Now()), teatest.WithInitialTermSize(120, 40))
	waitFor(t, tm, "RAM")
	tm.Type(menuTo("SSH"))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "SSH is not hardened yet")
	tm.Type("p2222")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	v := ctrlCView(t, tm)
	if strings.Contains(v, "Change the SSH port") || sim.listening != 22 || len(sim.ufw) != 2 || h.actionLog() != "" {
		t.Errorf("listening %d, rules %q, Task History %q\n%s", sim.listening, sim.ufw, h.actionLog(), v)
	}
}

// Root on the provider console has no SUDO_USER: the change form also asks
// the login user to try at the Verify Gate, defaulting to the first usable
// Admin User (carol has no key, alice does).
func TestSSHPortChangeWithoutSudoUserAsksLoginUser(t *testing.T) {
	h, sim := portChangeHost(t)
	t.Setenv("SUDO_USER", "")
	h.fake.Results["getent passwd"] = system.Result{Stdout: "carol:x:1000:1000::/home/carol:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/bash\n"}
	h.fake.Results["getent group"] = system.Result{Stdout: "sudo:x:27:carol,alice\n"}
	h.fake.Results["getent shadow"] = system.Result{Stdout: "carol:!:19000:0:99999:7:::\nalice:!:19000:0:99999:7:::\n"}
	h.write("/etc/sudoers.d/99-vpsctl-carol", "carol ALL=(ALL:ALL) NOPASSWD: ALL\n")
	h.write("/etc/sudoers.d/99-vpsctl-alice", "alice ALL=(ALL:ALL) NOPASSWD: ALL\n")
	tm := changePort(t, h, sim, "2222")
	waitFor(t, tm, "ssh -p 2222 alice@10.0.0.2")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // Stop safely
	waitFor(t, tm, "restored pre-run SSH state")
	ctrlCView(t, tm)
}

// A login user that is not a Managed User is refused before anything runs.
func TestSSHPortChangeLoginUserMustBeManaged(t *testing.T) {
	h, sim := portChangeHost(t)
	t.Setenv("SUDO_USER", "")
	tm := teatest.NewTestModel(t, New(harden.NewMachine(sim, h.host, h.root, io.Discard), time.Now()), teatest.WithInitialTermSize(120, 40))
	waitFor(t, tm, "RAM")
	tm.Type(menuTo("SSH"))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "Active sessions")
	tm.Type("p2222")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyTab})
	for range 10 {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyBackspace})
	}
	tm.Type("mallory")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "not a Managed User")
	ctrlCView(t, tm)
	if h.actionLog() != "" {
		t.Errorf("Task History %q", h.actionLog())
	}
}

var ctrlC = tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl}

// ctrl+c at the Verify Gate in the panel is "Stop safely": the change is
// restored and the TUI stays open.
func TestCtrlCAtVerifyGateStopsSafely(t *testing.T) {
	h, sim := portChangeHost(t)
	tm := changePort(t, h, sim, "2222")
	waitFor(t, tm, "[ Stop safely ]")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyLeft}) // "Login works" selected
	tm.Send(ctrlC)
	waitFor(t, tm, "restored pre-run SSH state")
	ctrlCView(t, tm)
	if sim.listening != 22 || !slices.Equal(sim.ufw, []string{"ufw allow 22/tcp", "ufw allow 80/tcp"}) {
		t.Errorf("listening %d, rules %q", sim.listening, sim.ufw)
	}
}

// blockOn holds the command line cmd until release is closed.
type blockOn struct {
	system.Runner
	cmd     string
	release chan struct{}
}

func (b blockOn) Run(name string, args ...string) (system.Result, error) {
	if strings.Join(append([]string{name}, args...), " ") == b.cmd {
		<-b.release
	}
	return b.Runner.Run(name, args...)
}

// ctrl+c while the change runs (before the gate) does not quit: the TUI
// says it is busy and the Task carries on to the Verify Gate.
func TestCtrlCWhileChangeRunsIsIgnored(t *testing.T) {
	h, sim := portChangeHost(t)
	r := blockOn{sim, "sshd -t", make(chan struct{})}
	tm := changePortOn(t, h, r, "2222")
	waitFor(t, tm, "Stage A: SSH on port 2222")
	tm.Send(ctrlC)
	waitFor(t, tm, "busy")
	close(r.release)
	waitFor(t, tm, "[ Stop safely ]")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "restored pre-run SSH state")
	ctrlCView(t, tm)
	if sim.listening != 22 {
		t.Errorf("listening %d", sim.listening)
	}
}

// The Lockout Guard refuses a port something already listens on in the
// form, before anything runs.
func TestSSHPortChangeRefusesListeningPort(t *testing.T) {
	h, sim := portChangeHost(t)
	h.fake.Results["ss -Hltunp"] = ssOut // postgres on 5432
	tm := changePort(t, h, sim, "5432")
	waitFor(t, tm, "refused: port 5432 is already a Listening Port")
	ctrlCView(t, tm)
	if sim.listening != 22 || len(sim.ufw) != 2 || h.actionLog() != "" {
		t.Errorf("listening %d, rules %q, Task History %q", sim.listening, sim.ufw, h.actionLog())
	}
}
