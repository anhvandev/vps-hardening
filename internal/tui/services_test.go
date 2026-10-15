package tui

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

// svcHost is debianHost with five Services: cron and ssh running, nginx
// failed, redis enabled but stopped, postfix stopped and disabled.
func svcHost(t *testing.T) *testHost {
	h := debianHost(t)
	h.fake.Results["systemctl list-units --type=service --all --plain --no-legend --no-pager"] = system.Result{Stdout: "" +
		"cron.service    loaded active   running Regular background program processing daemon\n" +
		"nginx.service   loaded failed   failed  A high performance web server\n" +
		"postfix.service loaded inactive dead    Postfix Mail Transport Agent\n" +
		"ssh.service     loaded active   running OpenBSD Secure Shell server\n"}
	h.fake.Results["systemctl list-unit-files --type=service --plain --no-legend --no-pager"] = system.Result{Stdout: "" +
		"cron.service enabled enabled\nnginx.service enabled enabled\npostfix.service disabled enabled\n" +
		"redis.service enabled enabled\nssh.service enabled enabled\n"}
	if err := os.MkdirAll(filepath.Join(h.root, "/run"), 0o755); err != nil {
		t.Fatal(err)
	}
	return h
}

// openServicesWith opens the Services screen on h, loaded, then presses keys.
func openServicesWith(h *testHost, keys string) tea.Model {
	s := screens["Services"](harden.NewMachine(h.fake, h.host, h.root, io.Discard))
	s, _ = s.Update(s.Init()())
	return press(s, keys)
}

func TestServicesListFilterAndToggle(t *testing.T) {
	h := svcHost(t)
	v := view(openServicesWith(h, ""))
	wantAll(t, v, "cron.service", "active (running)", "nginx.service", "failed (failed)", "redis.service", "ssh.service")
	if strings.Contains(v, "postfix") {
		t.Errorf("stopped, disabled Service shown by default:\n%s", v)
	}

	v = view(openServicesWith(h, "a"))
	wantAll(t, v, "postfix.service", "inactive (dead)", "disabled", "cron.service")

	v = view(openServicesWith(h, "a/post"))
	wantAll(t, v, "filter: post", "postfix.service")
	if strings.Contains(v, "cron.service") {
		t.Errorf("filter did not narrow:\n%s", v)
	}
}

// openServices starts the TUI on h and focuses the loaded Services screen.
func openServices(t *testing.T, h *testHost) *teatest.TestModel {
	t.Helper()
	tm := start(h)
	waitFor(t, tm, "RAM")
	tm.Type("jjjjj")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "cron.service")
	return tm
}

func closeServices(t *testing.T, tm *teatest.TestModel) string {
	t.Helper()
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape})
	waitFor(t, tm, "q quit")
	return quitView(t, tm)
}

func TestServicesRestart(t *testing.T) {
	h := svcHost(t)
	h.fake.Results["systemctl restart cron.service"] = system.Result{}
	tm := openServices(t, h)
	tm.Type("r") // first row: cron.service
	waitFor(t, tm, "restarted cron.service: active (running), enabled")
	closeServices(t, tm)
	if log := h.actionLog(); strings.Count(log, "\n") != 1 || !strings.Contains(log, "service restart cron.service: ok") {
		t.Errorf("action log:\n%s", log)
	}
}

func TestServicesRefusesStoppingSSH(t *testing.T) {
	h := svcHost(t)
	tm := openServices(t, h)
	tm.Type("jjjx") // cron, nginx, redis, ssh
	waitFor(t, tm, "refused: ssh.service is a Protected Unit (remote SSH access), cannot stop it")
	closeServices(t, tm)
	for _, c := range h.fake.Calls {
		if strings.HasPrefix(c, "systemctl stop") {
			t.Errorf("ran %q", c)
		}
	}
	if log := h.actionLog(); !strings.Contains(log, "service stop ssh.service: failed: refused") {
		t.Errorf("action log:\n%s", log)
	}
}

// Each lifecycle key runs its systemctl verb; a systemctl error is shown.
func TestServicesActions(t *testing.T) {
	h := svcHost(t)
	for _, c := range []string{"stop", "enable", "disable"} {
		h.fake.Results["systemctl "+c+" cron.service"] = system.Result{}
	}
	h.fake.Results["systemctl start nginx.service"] = system.Result{Code: 1, Stderr: "Job for nginx.service failed.\n"}
	for keys, want := range map[string]string{
		"x":  "stopped cron.service",
		"e":  "enabled cron.service",
		"d":  "disabled cron.service",
		"js": "Job for nginx.service failed.",
	} {
		if v := view(openServicesWith(h, keys)); !strings.Contains(v, want) {
			t.Errorf("%q: want %q in\n%s", keys, want, v)
		}
	}
	if log := h.actionLog(); strings.Count(log, ": ok\n") != 3 || !strings.Contains(log, "service start nginx.service: failed: ") {
		t.Errorf("action log:\n%s", log)
	}
}
