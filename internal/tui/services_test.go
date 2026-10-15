package tui

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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

// svcW, svcH is the size the Services screen gets in the 120×40 test terminal.
const svcW, svcH = 92, 36

// openServicesWith opens the Services screen on h, sized and loaded, then
// presses keys.
func openServicesWith(h *testHost, keys string) tea.Model {
	s := screens["Services"](harden.NewMachine(h.fake, h.host, h.root, io.Discard))
	s, _ = s.Update(tea.WindowSizeMsg{Width: svcW, Height: svcH})
	s, _ = s.Update(s.Init()())
	return press(s, keys)
}

func TestServicesListFilterAndToggle(t *testing.T) {
	h := svcHost(t)
	s := openServicesWith(h, "")
	v := view(s)
	wantAll(t, v, "filter: [ running·enabled·failed ▾ ]", "cron.service", "● running", "nginx.service", "✗ failed",
		"redis.service", "· dead", "ssh.service", "◆ Protected Unit")
	if strings.Contains(v, "postfix") {
		t.Errorf("stopped, disabled Service shown by default:\n%s", v)
	}

	v = view(press(s, "f"))
	wantAll(t, v, "filter: [ all ▾ ]", "postfix.service", "disabled", "cron.service")

	// a click on the dropdown switches it too
	x := strings.Index(strings.Split(view(s), "\n")[0], "filter: [")
	s, _ = s.Update(click(x+3, 0))
	wantAll(t, view(s), "filter: [ all ▾ ]", "postfix.service")

	v = view(press(s, "/post"))
	wantAll(t, v, "/ post", "postfix.service")
	if strings.Contains(v, "cron.service") {
		t.Errorf("name filter did not narrow:\n%s", v)
	}
}

// openServices starts the TUI on h and focuses the loaded Services screen.
func openServices(t *testing.T, h *testHost) *teatest.TestModel {
	t.Helper()
	tm := start(h)
	waitFor(t, tm, "RAM")
	tm.Type(menuTo("Services"))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "cron.service")
	return tm
}

// send presses each key name ("enter", "esc", "up", "down", "backspace") or
// types the literal text.
func send(tm *teatest.TestModel, ks ...string) {
	special := map[string]rune{"enter": tea.KeyEnter, "esc": tea.KeyEscape, "down": tea.KeyDown, "up": tea.KeyUp, "backspace": tea.KeyBackspace}
	for _, k := range ks {
		if code, ok := special[k]; ok {
			tm.Send(tea.KeyPressMsg{Code: code})
		} else {
			tm.Type(k)
		}
	}
}

// The shell's clock refreshes the open Services every 5 s.
func TestServicesRefreshTick(t *testing.T) {
	h := svcHost(t)
	tm := openServices(t, h)
	h.fake.Results["systemctl list-units --type=service --all --plain --no-legend --no-pager"] = system.Result{Stdout: "" +
		"cron.service    loaded active   running Regular background program processing daemon\n" +
		"worker.service  loaded failed   failed  Queue worker\n"}
	tm.Send(tickMsg{now: time.Now().Add(refreshEvery + time.Second)})
	waitFor(t, tm, "worker.service")
	ctrlCView(t, tm)
}

// Restart asks Yes/No, then runs as a Task: one Task History line.
func TestServicesRestartTask(t *testing.T) {
	h := svcHost(t)
	h.fake.Results["systemctl restart cron.service"] = system.Result{}
	tm := openServices(t, h)
	tm.Type("R") // first row: cron.service
	waitFor(t, tm, "Restart cron.service?")
	tm.Type("y")
	waitFor(t, tm, "Done in")
	wantAll(t, ctrlCView(t, tm), "SUMMARY  restarted cron.service", "Task: Restart cron.service", "Done in")
	if !slices.Contains(h.fake.Calls, "systemctl restart cron.service") {
		t.Errorf("not restarted: %q", h.fake.Calls)
	}
	if log := h.actionLog(); strings.Count(log, "\n") != 1 || !strings.Contains(log, "service restart cron.service: ok") {
		t.Errorf("Task History:\n%s", log)
	}
}

// ssh is a Protected Unit: Stop, Restart, Disable, Edit and Revert are
// disabled with the reason, and their keys ask, run and log nothing.
func TestServicesRefusesStoppingSSH(t *testing.T) {
	h := svcHost(t)
	marker := filepath.Join(t.TempDir(), "ran")
	t.Setenv("EDITOR", "touch "+marker)
	tm := openServices(t, h)
	tm.Type("jjjxRDe") // cron, nginx, redis, ssh
	v := ctrlCView(t, tm)
	wantAll(t, v, "ssh.service", "◆ Protected Unit",
		"◆ Stop, Restart, Disable, Edit, Revert disabled by the Lockout Guard: ssh.service is a", "Protected Unit (remote SSH access)")
	if strings.Contains(v, "Stop ssh.service?") || strings.Contains(v, "Task:") {
		t.Errorf("disabled action asked or ran:\n%s", v)
	}
	for _, c := range h.fake.Calls {
		if strings.HasPrefix(c, "systemctl stop") || strings.HasPrefix(c, "systemctl restart") || strings.HasPrefix(c, "systemctl disable") {
			t.Errorf("ran %q", c)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("editor opened for a Protected Unit")
	}
	if log := h.actionLog(); log != "" {
		t.Errorf("Task History:\n%s", log)
	}
}

// Each lifecycle key runs its systemctl verb as a Task; a systemctl error
// fails the Task with it.
func TestServicesActions(t *testing.T) {
	for _, c := range []struct{ keys, cmd, want string }{
		{"x", "systemctl stop cron.service", "service stop cron.service: ok"},
		{"E", "systemctl enable cron.service", "service enable cron.service: ok"},
		{"D", "systemctl disable cron.service", "service disable cron.service: ok"},
		{"js", "systemctl start nginx.service", "service start nginx.service: failed: systemctl start nginx.service: exit 1: Job for nginx.service failed."},
	} {
		h := svcHost(t)
		h.fake.Results[c.cmd] = system.Result{}
		if c.keys == "js" {
			h.fake.Results[c.cmd] = system.Result{Code: 1, Stderr: "Job for nginx.service failed.\n"}
		}
		tm := openServices(t, h)
		tm.Type(c.keys + "y")
		waitFor(t, tm, map[bool]string{false: "Done in", true: "Failed"}[c.keys == "js"])
		ctrlCView(t, tm)
		if !slices.Contains(h.fake.Calls, c.cmd) {
			t.Errorf("%q: did not run %q", c.keys, c.cmd)
		}
		if log := h.actionLog(); strings.Count(log, "\n") != 1 || !strings.Contains(log, c.want) {
			t.Errorf("%q: Task History:\n%s", c.keys, log)
		}
	}
}
