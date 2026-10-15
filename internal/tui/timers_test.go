package tui

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

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

// openTimers opens the Timers screen on h, sized and loaded, then presses ks
// (see keys).
func openTimers(h *testHost, ks ...string) tea.Model {
	s := screens["Timers"](harden.NewMachine(h.fake, h.host, h.root, io.Discard))
	s, _ = s.Update(tea.WindowSizeMsg{Width: svcW, Height: svcH})
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

// An invalid schedule is refused inline before anything is written or logged.
func TestTimersCreateRejectsBadSchedule(t *testing.T) {
	h := createTimerHost(t)
	s := openTimers(h, "a", "backup", "down", "bogus", "down", "backup", "enter")
	wantAll(t, view(s), "New Timer", "Failed to parse calendar specification 'bogus'")
	if _, err := os.Stat(service.UnitPath(h.root, "backup.timer")); !os.IsNotExist(err) {
		t.Errorf("timer written with an invalid schedule: %v", err)
	}
	if log := h.actionLog(); log != "" {
		t.Errorf("rejected form logged:\n%s", log)
	}
}

// openTimersTUI starts the TUI on h and focuses the loaded Timers screen.
func openTimersTUI(t *testing.T, h *testHost) *teatest.TestModel {
	t.Helper()
	tm := start(h)
	waitFor(t, tm, "RAM")
	tm.Type(menuTo("Timers"))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "logrotate.timer")
	return tm
}

// A valid Timer is created, enabled and started as one Task, then listed
// with its next run.
func TestTimersCreateTask(t *testing.T) {
	h := createTimerHost(t)
	tm := openTimersTUI(t, h)
	h.fake.Results["systemctl list-timers --all --plain --no-legend --no-pager"] = system.Result{Stdout: "" +
		"Fri 2026-10-16 03:00:00 UTC 9h left - - backup.timer backup.service\n"}
	tm.Type("a")
	send(tm, "backup", "down", "*-*-* 03:00", "down", "backup", "enter")
	waitFor(t, tm, "Done in")
	send(tm, "enter") // close the card
	v := ctrlCView(t, tm)
	wantAll(t, v, "backup.timer", "Fri 2026-10-16 03:00:00 UTC", "backup.service")
	if strings.Contains(v, "New Timer") {
		t.Errorf("form still open:\n%s", v)
	}
	want := "[Unit]\nDescription=Run backup.service on *-*-* 03:00\n\n[Timer]\nOnCalendar=*-*-* 03:00\nUnit=backup.service\n\n" +
		"[Install]\nWantedBy=timers.target\n"
	if got := readFile(t, service.UnitPath(h.root, "backup.timer")); got != want {
		t.Errorf("unit = %q", got)
	}
	if !slices.Contains(h.fake.Calls, "systemctl start backup.timer") {
		t.Errorf("not started: %q", h.fake.Calls)
	}
	if log := h.actionLog(); strings.Count(log, "\n") != 1 || !strings.Contains(log, "timer create backup.timer: ok") {
		t.Errorf("Task History:\n%s", log)
	}
}

func TestTimersCreateRefusedWhileLocked(t *testing.T) {
	h := createTimerHost(t)
	lk, err := actionlog.Lock(filepath.Join(h.root, actionlog.LockPath))
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Close()
	tm := openTimersTUI(t, h)
	tm.Type("a")
	send(tm, "backup", "down", "*-*-* 03:00", "down", "backup", "enter")
	waitFor(t, tm, "refused: locked by ")
	wantAll(t, ctrlCView(t, tm), "New Timer")
	if _, err := os.Stat(service.UnitPath(h.root, "backup.timer")); !os.IsNotExist(err) {
		t.Errorf("timer written while locked: %v", err)
	}
}

func TestTimersListNextRunAndService(t *testing.T) {
	v := view(openTimers(timerHost(t)))
	wantAll(t, v, "TIMER", "NEXT RUN", "SERVICE",
		"fstrim.timer", "logrotate.timer", "Thu 2026-10-15 00:00:00 UTC", "logrotate.service", "[ + New ]")
}

// Editing a packaged Timer writes an override as a Task; a failed verify
// applies nothing and the copy can be discarded.
func TestTimersEditOverride(t *testing.T) {
	h := timerHost(t)
	h.fake.Results["systemd-analyze verify logrotate.timer"] = system.Result{Code: 1, Stderr: "override.conf:2: Unknown key name 'OnCalender'\n"}
	h.fake.Results["systemctl daemon-reload"] = system.Result{}
	fakeEditor(t, `[Timer]\nOnCalender=weekly\n`)
	tm := openTimersTUI(t, h)
	tm.Type("je") // fstrim, logrotate
	waitFor(t, tm, "nothing applied · enter re-edit · esc discard")
	if _, err := os.Stat(service.OverridePath(h.root, "logrotate.timer")); !os.IsNotExist(err) {
		t.Errorf("invalid override left behind: %v", err)
	}
	send(tm, "esc", "esc") // close the Failed card, discard
	waitFor(t, tm, "discarded edit of logrotate.timer")

	h.fake.Results["systemd-analyze verify logrotate.timer"] = system.Result{}
	fakeEditor(t, `[Timer]\nOnCalendar=\nOnCalendar=weekly\n`)
	tm.Type("e")
	waitFor(t, tm, "Done in")
	wantAll(t, ctrlCView(t, tm), "SUMMARY  override for logrotate.timer applied, systemd reloaded")
	if got := readFile(t, service.OverridePath(h.root, "logrotate.timer")); got != "[Timer]\nOnCalendar=\nOnCalendar=weekly\n" {
		t.Errorf("override = %q", got)
	}
	if lockBusy(h) {
		t.Error("global lock still held")
	}
	log := h.actionLog()
	if !strings.Contains(log, "timer edit logrotate.timer: failed: ") || !strings.Contains(log, "timer edit logrotate.timer: ok") {
		t.Errorf("Task History:\n%s", log)
	}
}

func TestTimersRevertOverride(t *testing.T) {
	h := timerHost(t)
	h.write("/etc/systemd/system/logrotate.timer.d/override.conf", "[Timer]\nOnCalendar=\nOnCalendar=weekly\n")
	h.fake.Results["systemctl daemon-reload"] = system.Result{}
	tm := openTimersTUI(t, h)
	tm.Type("jU")
	waitFor(t, tm, "Revert logrotate.timer override?")
	tm.Type("y")
	waitFor(t, tm, "Done in")
	wantAll(t, ctrlCView(t, tm), "SUMMARY  reverted logrotate.timer override, systemd reloaded")
	if _, err := os.Stat(service.OverridePath(h.root, "logrotate.timer")); !os.IsNotExist(err) {
		t.Errorf("override still there: %v", err)
	}
	if log := h.actionLog(); !strings.Contains(log, "timer revert logrotate.timer: ok") {
		t.Errorf("Task History:\n%s", log)
	}
}
