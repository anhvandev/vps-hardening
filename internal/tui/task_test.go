package tui

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/actionlog"
	"github.com/anhvandev/vpsctl/internal/system"
)

// taskOutputs is the content of every Task output file under h's root.
func taskOutputs(t *testing.T, h *testHost) []string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(h.root, actionlog.TaskDir, "*.log"))
	var outs []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		outs = append(outs, string(b))
	}
	return outs
}

// oneOutput is the only Task output file under h's root.
func oneOutput(t *testing.T, h *testHost) string {
	t.Helper()
	outs := taskOutputs(t, h)
	if len(outs) != 1 {
		t.Fatalf("want one Task output file, got %q", outs)
	}
	return outs[0]
}

// Opening a port runs as a Task: a Done card with the summary that can show
// the command's output; one Task History entry plus its output file.
func TestFirewallOpenPortTask(t *testing.T) {
	h := debianHost(t)
	h.fake.Results["ufw allow 8080/tcp"] = system.Result{Stdout: "Rule added\nRule added (v6)\n"}
	tm := openFirewall(t, h)
	tm.Type("a8080/tcp")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "SUMMARY  opened 8080/tcp")
	tm.Type("o") // view full output
	waitFor(t, tm, "Rule added (v6)")
	v := ctrlCView(t, tm)
	wantAll(t, v, "Task: Open port 8080/tcp", "Done in", "$ ufw allow 8080/tcp", "Rule added (v6)", "[ Close ]")

	if log := actionLog(t, h); strings.Count(log, "\n") != 1 || !strings.Contains(log, "firewall open 8080/tcp: ok") {
		t.Errorf("Task History:\n%s", log)
	}
	wantAll(t, oneOutput(t, h), "Open port 8080/tcp", "[step 1/1] Allow 8080/tcp", "$ ufw allow 8080/tcp", "Rule added (v6)", "Done: opened 8080/tcp")
}

// A running Task shows its steps and live output; it can be hidden into the
// status bar and keeps running while the operator moves to another screen;
// a second Task is refused meanwhile, and quitting is blocked. Clicking the
// status bar reopens it, and its result is delivered.
func TestTaskHideReopenAndQuitBlocked(t *testing.T) {
	h := debianHost(t)
	h.fake.Results["ufw allow 8080/tcp"] = system.Result{Stdout: "Rule added\n"}
	r := blockOn{h.fake, "ufw allow 8080/tcp", make(chan struct{})}
	tm := openFirewallOn(t, h, r)
	tm.Type("a8080/tcp")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "$ ufw allow 8080/tcp")        // running: the command line is in the output
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape}) // Hide
	waitFor(t, tm, "(click to open)")

	tm.Type("a9090/tcp") // a second Task while the first runs
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, `refused: Task "Open port 8080/tcp" is running`)

	overview := slices.IndexFunc(sideRows(), func(r sideRow) bool { return r.text == "Overview" })
	tm.Send(tea.MouseClickMsg{X: 5, Y: 1 + overview, Button: tea.MouseLeft}) // open Overview
	waitFor(t, tm, "RAM")
	tm.Send(ctrlC)
	waitFor(t, tm, "busy")

	tm.Send(tea.MouseClickMsg{X: 10, Y: 38, Button: tea.MouseLeft}) // the status bar
	waitFor(t, tm, "Task: Open port 8080/tcp")
	close(r.release)
	waitFor(t, tm, "SUMMARY  opened 8080/tcp")
	v := ctrlCView(t, tm)
	wantAll(t, v, "Overview", "Done in")

	if got := mutations(h); !slices.Equal(got, []string{"ufw allow 8080/tcp"}) {
		t.Errorf("ran %q", got)
	}
	if log := actionLog(t, h); strings.Count(log, "\n") != 1 || !strings.Contains(log, "firewall open 8080/tcp: ok") {
		t.Errorf("Task History:\n%s", log)
	}
}

// A step's error marked quiet (it may carry a secret, e.g. a Cron Entry's
// command) shows in full on the Failed card only: the output file and Task
// History get a bare "failed".
func TestTaskOutputKeepsQuietErrorsOut(t *testing.T) {
	h := debianHost(t)
	h.write("/run/.keep", "")
	tm := start(h)
	waitFor(t, tm, "RAM")
	tm.Send(runTask("Add Cron Entry", "cron add root", "added",
		taskStep{"Install crontab", func(_ system.Runner, out io.Writer) error {
			io.WriteString(out, "installing crontab for root\n")
			return quiet{errors.New("bad minute in: 61 * * * * curl -H token:s3cret")}
		}})())
	waitFor(t, tm, "s3cret")
	v := ctrlCView(t, tm)
	wantAll(t, v, "Failed", `step 1/1 "Install crontab"`)

	log := actionLog(t, h)
	if strings.Contains(log, "s3cret") || !strings.Contains(log, "cron add root: failed\n") {
		t.Errorf("Task History:\n%s", log)
	}
	out := oneOutput(t, h)
	if strings.Contains(out, "s3cret") {
		t.Errorf("output file leaks the secret:\n%s", out)
	}
	wantAll(t, out, "installing crontab for root", `step 1/1 "Install crontab" failed`)
}

// While another session holds the global lock, the status bar says who.
func TestStatusBarShowsLockHolder(t *testing.T) {
	t.Setenv("SUDO_USER", "alice")
	h := debianHost(t)
	h.write("/run/.keep", "")
	lk, err := actionlog.Lock(filepath.Join(h.root, actionlog.LockPath))
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Close()
	tm := start(h)
	waitFor(t, tm, "locked by alice (pid ")
	ctrlCView(t, tm)
}
