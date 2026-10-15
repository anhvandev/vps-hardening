package tui

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/anhvandev/vpsctl/internal/actionlog"
	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

// crontabHost is h's fake runner plus a fake crontab tool over tabs.
type crontabHost struct {
	*system.Fake
	tabs map[string]string
}

func (c crontabHost) Run(name string, args ...string) (system.Result, error) {
	if name != "crontab" || len(args) != 3 || args[0] != "-u" {
		return c.Fake.Run(name, args...)
	}
	if args[2] == "-l" {
		tab, ok := c.tabs[args[1]]
		if !ok {
			return system.Result{Code: 1, Stderr: "no crontab for " + args[1]}, nil
		}
		return system.Result{Stdout: tab}, nil
	}
	b, err := os.ReadFile(args[2])
	c.tabs[args[1]] = string(b)
	return system.Result{}, err
}

// cronHost is debianHost with Managed User alice, a root crontab with a
// comment and an environment line, and no crontab for alice.
func cronHost(t *testing.T) (*testHost, crontabHost) {
	h := debianHost(t)
	h.fake.Results["getent passwd"] = system.Result{Stdout: "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"}
	h.fake.Results["getent group"] = system.Result{Stdout: "sudo:x:27:alice\n"}
	h.fake.Results["getent shadow"] = system.Result{Stdout: "alice:!:19000:0:99999:7:::\n"}
	if err := os.MkdirAll(filepath.Join(h.root, "/run"), 0o755); err != nil {
		t.Fatal(err)
	}
	return h, crontabHost{h.fake, map[string]string{"root": "# nightly\nMAILTO=ops@example.com\n0 3 * * * /usr/local/bin/backup\n"}}
}

// cronScreenOn opens the Cron screen on h with the fake crontab, loaded.
func cronScreenOn(h *testHost, c crontabHost) tea.Model {
	s := screens["Cron"](harden.NewMachine(c, h.host, h.root, io.Discard))
	return pump(s, s.Init()())
}

// pump feeds msg to s, then every message its commands produce.
func pump(s tea.Model, msg tea.Msg) tea.Model {
	for msg != nil {
		var cmd tea.Cmd
		s, cmd = s.Update(msg)
		msg = nil
		if cmd != nil {
			msg = cmd()
		}
	}
	return s
}

// keys presses each key name: "enter", "esc", "down", "backspace", or a
// literal text typed rune by rune.
func keys(s tea.Model, ks ...string) tea.Model {
	special := map[string]rune{"enter": tea.KeyEnter, "esc": tea.KeyEscape, "down": tea.KeyDown, "up": tea.KeyUp, "backspace": tea.KeyBackspace}
	for _, k := range ks {
		if code, ok := special[k]; ok {
			s = pump(s, tea.KeyPressMsg{Code: code})
			continue
		}
		for _, r := range k {
			s = pump(s, tea.KeyPressMsg{Code: r, Text: string(r)})
		}
	}
	return s
}

func view(s tea.Model) string { return ansi.Strip(s.View().Content) }

func actionLog(t *testing.T, h *testHost) string {
	b, _ := os.ReadFile(filepath.Join(h.root, actionlog.LogPath))
	return string(b)
}

func TestCronListsRootAndManagedUsers(t *testing.T) {
	h, c := cronHost(t)
	c.tabs["alice"] = "@reboot /home/alice/start.sh\n"
	v := view(cronScreenOn(h, c))
	wantAll(t, v, "root", "0 3 * * * /usr/local/bin/backup", "alice", "@reboot /home/alice/start.sh")
	if strings.Contains(v, "MAILTO") || strings.Contains(v, "nightly") {
		t.Errorf("comment or environment line listed as an entry:\n%s", v)
	}
}

func TestCronAddEditDelete(t *testing.T) {
	h, c := cronHost(t)
	s := cronScreenOn(h, c)

	// rows: root, root's entry, alice
	s = keys(s, "down", "down", "a", "*/5 * * * * /home/alice/poll", "enter")
	if c.tabs["alice"] != "*/5 * * * * /home/alice/poll\n" {
		t.Fatalf("alice's crontab = %q", c.tabs["alice"])
	}
	wantAll(t, view(s), "*/5 * * * * /home/alice/poll")

	s = keys(s, "up", "e", " --fulll", "backspace", "enter")
	if want := "# nightly\nMAILTO=ops@example.com\n0 3 * * * /usr/local/bin/backup --full\n"; c.tabs["root"] != want {
		t.Fatalf("root's crontab = %q, want %q", c.tabs["root"], want)
	}

	s = keys(s, "d", "n")
	if !strings.Contains(c.tabs["root"], "backup --full") {
		t.Fatal("deleted without confirmation")
	}
	s = keys(s, "d", "y")
	if c.tabs["root"] != "# nightly\nMAILTO=ops@example.com\n" {
		t.Fatalf("root's crontab after delete = %q", c.tabs["root"])
	}
	if strings.Contains(view(s), "backup") {
		t.Errorf("deleted entry still listed:\n%s", view(s))
	}

	log := actionLog(t, h)
	for _, want := range []string{"cron add alice: ok", "cron edit root: ok", "cron delete root: ok"} {
		if !strings.Contains(log, want) {
			t.Errorf("action log missing %q:\n%s", want, log)
		}
	}
	if n := strings.Count(log, "\n"); n != 3 {
		t.Errorf("action log has %d lines, want 3:\n%s", n, log)
	}
}

func TestCronRejectsInvalidSchedule(t *testing.T) {
	h, c := cronHost(t)
	s := keys(cronScreenOn(h, c), "a", "61 * * * * /bin/true", "enter")
	if _, ok := c.tabs["root"]; !ok || strings.Contains(c.tabs["root"], "/bin/true") {
		t.Fatalf("invalid entry written: %q", c.tabs["root"])
	}
	wantAll(t, view(s), "minute", "61 * * * * /bin/true") // error shown, input kept to fix
	if log := actionLog(t, h); log != "" {
		t.Errorf("rejected input logged:\n%s", log)
	}
	s = keys(s, "esc")
	if strings.Contains(view(s), "61 *") {
		t.Errorf("esc kept the form:\n%s", view(s))
	}
	if _, cmd := s.Update(tea.KeyPressMsg{Code: tea.KeyEscape}); cmd == nil || cmd() != Back() {
		t.Error("esc on the list does not go back")
	}
}

func TestCronLockBusy(t *testing.T) {
	h, c := cronHost(t)
	lk, err := actionlog.Lock(filepath.Join(h.root, actionlog.LockPath))
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Close()
	s := keys(cronScreenOn(h, c), "a", "@daily /bin/true", "enter")
	wantAll(t, view(s), "locked by")
	if strings.Contains(c.tabs["root"], "/bin/true") {
		t.Error("crontab written without the lock")
	}
}
