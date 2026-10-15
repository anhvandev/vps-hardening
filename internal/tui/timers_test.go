package tui

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/harden"
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

func TestTimersListNextRunAndService(t *testing.T) {
	v := view(openTimers(timerHost(t)))
	wantAll(t, v, "Timer", "Next run", "Service",
		"fstrim.timer", "logrotate.timer", "Thu 2026-10-15 00:00:00 UTC", "logrotate.service")
}
