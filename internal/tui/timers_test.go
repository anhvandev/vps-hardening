package tui

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/actionlog"
	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/service"
	"github.com/anhvandev/vpsctl/internal/system"
)

// timerHost is debianHost with two Timers: logrotate scheduled, fstrim
// installed but not loaded.
func timerHost(t *testing.T) *testHost {
	h := debianHost(t)
	h.fake.Results["systemctl list-timers --all --plain --no-legend --no-pager"] = system.Result{Stdout: "" +
		"Thu 2026-10-15 00:00:00 UTC 5h left Wed 2026-10-14 00:00:00 UTC 18h ago logrotate.timer logrotate.service\n"}
	h.fake.Results["systemctl list-unit-files --type=timer --plain --no-legend --no-pager"] = system.Result{Stdout: "" +
		"fstrim.timer disabled enabled\nlogrotate.timer enabled enabled\n"}
	if err := os.MkdirAll(filepath.Join(h.root, "/run"), 0o755); err != nil {
		t.Fatal(err)
	}
	return h
}

// openTimers opens the Timers screen on h, loaded, then presses ks (see keys).
func openTimers(h *testHost, ks ...string) tea.Model {
	s := screens["Timers"](harden.NewMachine(h.fake, h.host, h.root, io.Discard))
	return keys(pump(s, s.Init()()), ks...)
}

// createTimerHost is timerHost with backup.service to schedule and
// backup.timer free to create.
func createTimerHost(t *testing.T) *testHost {
	h := timerHost(t)
	h.fake.Results["systemd-analyze calendar bogus"] = system.Result{Code: 1, Stderr: "Failed to parse calendar specification 'bogus': Invalid argument\n"}
	h.fake.Results["systemd-analyze calendar *-*-* 03:00"] = system.Result{Stdout: "Normalized form: *-*-* 03:00:00\n"}
	h.fake.Results["systemctl show -p LoadState --value backup.service"] = system.Result{Stdout: "loaded\n"}
	h.fake.Results["systemctl show -p LoadState --value backup.timer"] = system.Result{Stdout: "not-found\n"}
	h.fake.Results["systemd-analyze verify backup.timer"] = system.Result{}
	h.fake.Results["systemctl daemon-reload"] = system.Result{}
	h.fake.Results["systemctl enable backup.timer"] = system.Result{}
	h.fake.Results["systemctl start backup.timer"] = system.Result{}
	return h
}

// An invalid schedule is refused before anything is written; a valid one
// creates, enables and starts the Timer and shows its next run.
func TestTimersCreateFromForm(t *testing.T) {
	h := createTimerHost(t)
	s := openTimers(h, "n", "backup", "down", "bogus", "down", "backup", "enter")
	wantAll(t, view(s), "New Timer", "Failed to parse calendar specification 'bogus'")
	if _, err := os.Stat(service.UnitPath(h.root, "backup.timer")); !os.IsNotExist(err) {
		t.Errorf("timer written with an invalid schedule: %v", err)
	}
	if log := h.actionLog(); log != "" {
		t.Errorf("rejected form logged:\n%s", log)
	}

	h.fake.Results["systemctl list-timers --all --plain --no-legend --no-pager"] = system.Result{Stdout: "" +
		"Fri 2026-10-16 03:00:00 UTC 9h left - - backup.timer backup.service\n"}
	s = keys(s, "up", "backspace", "backspace", "backspace", "backspace", "backspace", "*-*-* 03:00", "enter")
	wantAll(t, view(s), "created backup.timer, next run Fri 2026-10-16 03:00:00 UTC", "backup.service")
	want := "[Unit]\nDescription=Run backup.service on *-*-* 03:00\n\n[Timer]\nOnCalendar=*-*-* 03:00\nUnit=backup.service\n\n" +
		"[Install]\nWantedBy=timers.target\n"
	if got := readFile(t, service.UnitPath(h.root, "backup.timer")); got != want {
		t.Errorf("unit = %q", got)
	}
	if !slices.Contains(h.fake.Calls, "systemctl start backup.timer") {
		t.Errorf("not started: %q", h.fake.Calls)
	}
	log := h.actionLog()
	for _, w := range []string{"timer create backup.timer: ok", "timer enable+start backup.timer: ok"} {
		if !strings.Contains(log, w) {
			t.Errorf("action log missing %q:\n%s", w, log)
		}
	}
}

func TestTimersCreateRefusedWhileLocked(t *testing.T) {
	h := createTimerHost(t)
	lk, err := actionlog.Lock(filepath.Join(h.root, actionlog.LockPath))
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Close()
	s := openTimers(h, "n", "backup", "down", "*-*-* 03:00", "down", "backup", "enter")
	wantAll(t, view(s), "New Timer", "locked by ")
	if _, err := os.Stat(service.UnitPath(h.root, "backup.timer")); !os.IsNotExist(err) {
		t.Errorf("timer written while locked: %v", err)
	}
}

func TestTimersListNextRunAndService(t *testing.T) {
	v := view(openTimers(timerHost(t)))
	wantAll(t, v, "Timer", "Next run", "Service",
		"fstrim.timer", "logrotate.timer", "Thu 2026-10-15 00:00:00 UTC", "logrotate.service")
}
