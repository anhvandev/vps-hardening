package tui

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/exp/teatest/v2"

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
	s, _ = s.Update(tea.WindowSizeMsg{Width: 92, Height: 36})
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

// openCron starts the TUI on h, commands going through r, and opens Cron.
func openCron(t *testing.T, h *testHost, r system.Runner) *teatest.TestModel {
	t.Helper()
	tm := teatest.NewTestModel(t, New(harden.NewMachine(r, h.host, h.root, io.Discard), time.Now()), teatest.WithInitialTermSize(120, 40))
	waitFor(t, tm, "RAM")
	tm.Type(menuTo("Cron"))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "ENTRY")
	return tm
}

// cronOutputs is every Task output file, joined.
func cronOutputs(t *testing.T, h *testHost) string { return strings.Join(taskOutputs(t, h), "\n") }

// Adding a Cron Entry runs as a Task; the entry stays out of the Task's
// output and Task History (it may carry a secret).
func TestCronAddEntryAsTask(t *testing.T) {
	h, c := cronHost(t)
	tm := openCron(t, h, c)
	tm.Type("j") // rows: root's entry, alice (no entries)
	tm.Type("a*/5 * * * * /home/alice/poll?token=s3cret")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "SUMMARY  added a Cron Entry for alice")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // close the card
	v := ctrlCView(t, tm)
	if !lineHas(v, "alice", "*/5 * * * * /home/alice/poll?token=s3cret") {
		t.Errorf("added entry not listed:\n%s", v)
	}
	if c.tabs["alice"] != "*/5 * * * * /home/alice/poll?token=s3cret\n" {
		t.Errorf("alice's crontab = %q", c.tabs["alice"])
	}
	if log := actionLog(t, h); strings.Count(log, "\n") != 1 || !strings.HasSuffix(log, "cron add alice: ok\n") {
		t.Errorf("Task History:\n%s", log)
	}
	if out := cronOutputs(t, h); strings.Contains(out, "s3cret") || !strings.Contains(out, "Done: ") {
		t.Errorf("Task output:\n%s", out)
	}
}

// Editing runs as a Task whose output holds none of the crontab.
func TestCronEditEntry(t *testing.T) {
	h, c := cronHost(t)
	tm := openCron(t, h, c) // first row: root's backup entry
	tm.Type("e --fulll")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyBackspace})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "SUMMARY  edited a Cron Entry of root")
	ctrlCView(t, tm)
	if want := "# nightly\nMAILTO=ops@example.com\n0 3 * * * /usr/local/bin/backup --full\n"; c.tabs["root"] != want {
		t.Errorf("root's crontab = %q, want %q", c.tabs["root"], want)
	}
	if log := actionLog(t, h); strings.Count(log, "\n") != 1 || !strings.HasSuffix(log, "cron edit root: ok\n") {
		t.Errorf("Task History:\n%s", log)
	}
	if out := cronOutputs(t, h); strings.Contains(out, "backup") || strings.Contains(out, "MAILTO") {
		t.Errorf("Task output leaks the crontab:\n%s", out)
	}
}

// Deleting asks Yes/No first; No changes nothing, Yes deletes as a Task.
func TestCronDeleteAsksFirst(t *testing.T) {
	h, c := cronHost(t)
	tm := openCron(t, h, c)
	tm.Type("d")
	waitFor(t, tm, "Delete this Cron Entry of root?")
	tm.Type("n")
	tm.Type("d")
	tm.Type("y")
	waitFor(t, tm, "SUMMARY  deleted a Cron Entry of root")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	v := ctrlCView(t, tm)
	if strings.Contains(v, "backup") {
		t.Errorf("deleted entry still listed:\n%s", v)
	}
	if c.tabs["root"] != "# nightly\nMAILTO=ops@example.com\n" {
		t.Errorf("root's crontab = %q", c.tabs["root"])
	}
	if log := actionLog(t, h); strings.Count(log, "\n") != 1 || !strings.HasSuffix(log, "cron delete root: ok\n") {
		t.Errorf("Task History:\n%s", log)
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

// rejectInstall is a crontab that refuses every install, echoing the file.
type rejectInstall struct{ crontabHost }

func (r rejectInstall) Run(name string, args ...string) (system.Result, error) {
	if name == "crontab" && len(args) == 3 && args[2] != "-l" {
		b, _ := os.ReadFile(args[2])
		return system.Result{Code: 1, Stderr: "bad line: " + string(b)}, nil
	}
	return r.crontabHost.Run(name, args...)
}

// A failed save shows the error on the Failed card only: Task History and
// the output get a bare "failed", as the error may echo a Cron Entry's secrets.
func TestCronFailedSaveKeepsEntryOutOfLog(t *testing.T) {
	h, c := cronHost(t)
	tm := openCron(t, h, rejectInstall{c})
	tm.Type("a@daily curl -H TOKEN=hunter2 x")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "bad line")
	wantAll(t, ctrlCView(t, tm), "Failed")
	if log := actionLog(t, h); strings.Contains(log, "hunter2") || !strings.HasSuffix(log, "cron add root: failed\n") {
		t.Errorf("Task History:\n%s", log)
	}
	if out := cronOutputs(t, h); strings.Contains(out, "hunter2") {
		t.Errorf("Task output leaks the entry:\n%s", out)
	}
}

func TestCronLockBusy(t *testing.T) {
	h, c := cronHost(t)
	lk, err := actionlog.Lock(filepath.Join(h.root, actionlog.LockPath))
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Close()
	tm := openCron(t, h, c)
	tm.Type("a@daily /bin/true")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "refused: locked by")
	ctrlCView(t, tm)
	if strings.Contains(c.tabs["root"], "/bin/true") {
		t.Error("crontab written without the lock")
	}
}
