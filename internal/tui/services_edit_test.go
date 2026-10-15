package tui

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/anhvandev/vpsctl/internal/actionlog"
	"github.com/anhvandev/vpsctl/internal/service"
	"github.com/anhvandev/vpsctl/internal/system"
)

// fakeEditor points $EDITOR at a script that overwrites the file it is given
// with content.
func fakeEditor(t *testing.T, content string) {
	t.Helper()
	script := filepath.Join(t.TempDir(), "editor")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '"+content+"' > \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDITOR", script)
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// lockBusy reports whether someone holds the global lock under h's root.
func lockBusy(h *testHost) bool {
	lk, err := actionlog.Lock(filepath.Join(h.root, actionlog.LockPath))
	if err != nil {
		return true
	}
	lk.Close()
	return false
}

// A busy global lock refuses the edit before the editor opens.
func TestServicesEditRefusedWhileLocked(t *testing.T) {
	h := svcHost(t)
	marker := filepath.Join(t.TempDir(), "ran")
	t.Setenv("EDITOR", "touch "+marker)
	lk, err := actionlog.Lock(filepath.Join(h.root, actionlog.LockPath))
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Close()
	tm := openServices(t, h)
	tm.Type("e")
	waitFor(t, tm, "locked by ")
	ctrlCView(t, tm)
	if _, err := os.Stat(marker); err == nil {
		t.Error("editor opened while the lock is held elsewhere")
	}
}

// The saved override is verified and applied as a Task.
func TestServicesEditOverride(t *testing.T) {
	h := svcHost(t)
	h.fake.Results["systemd-analyze verify cron.service"] = system.Result{}
	h.fake.Results["systemctl daemon-reload"] = system.Result{}
	fakeEditor(t, `[Service]\nNice=5\n`)
	tm := openServices(t, h)
	tm.Type("e") // first row: cron.service
	waitFor(t, tm, "Done in")
	tm.Type("o")
	waitFor(t, tm, "$ systemctl daemon-reload")
	wantAll(t, ctrlCView(t, tm), "SUMMARY  override for cron.service applied, systemd reloaded")
	if got := readFile(t, service.OverridePath(h.root, "cron.service")); got != "[Service]\nNice=5\n" {
		t.Errorf("override = %q", got)
	}
	if log := h.actionLog(); strings.Count(log, "\n") != 1 || !strings.Contains(log, "service edit cron.service: ok") {
		t.Errorf("Task History:\n%s", log)
	}
	if lockBusy(h) {
		t.Error("global lock still held after apply")
	}
}

// Saving the override unchanged applies nothing and says so in the status bar.
func TestServicesEditUnchanged(t *testing.T) {
	h := svcHost(t)
	h.write("/etc/systemd/system/cron.service.d/override.conf", "[Service]\nNice=1\n")
	fakeEditor(t, `[Service]\nNice=1\n`)
	tm := openServices(t, h)
	tm.Type("e")
	waitFor(t, tm, "no changes to cron.service")
	if v := ctrlCView(t, tm); !strings.Contains(v, "\n│ no changes to cron.service") { // the status bar, left
		t.Errorf("notice not in the status bar:\n%s", v)
	}
	if strings.Contains(h.actionLog(), "cron.service") {
		t.Error("an unchanged override ran a Task")
	}
}

// A failed verify applies nothing: the previous override stays, systemd is not
// reloaded, and the operator can discard or re-edit the copy.
func TestServicesEditVerifyFailure(t *testing.T) {
	h := svcHost(t)
	h.write("/etc/systemd/system/cron.service.d/override.conf", "[Service]\nNice=1\n")
	h.fake.Results["systemd-analyze verify cron.service"] = system.Result{Code: 1, Stderr: "override.conf:2: Unknown key name 'Nise'\n"}
	fakeEditor(t, `[Service]\nNise=5\n`)
	tm := openServices(t, h)
	tm.Type("e")
	waitFor(t, tm, "nothing applied · enter re-edit · esc discard") // under the Failed card
	send(tm, "esc")                                                 // close it
	send(tm, "esc")
	waitFor(t, tm, "discarded edit of cron.service")
	if lockBusy(h) {
		t.Error("global lock still held after discard")
	}
	if got := readFile(t, service.OverridePath(h.root, "cron.service")); got != "[Service]\nNice=1\n" {
		t.Errorf("override after discard = %q", got)
	}

	tm.Type("e")
	waitFor(t, tm, "nothing applied · enter re-edit · esc discard")
	send(tm, "esc")
	h.fake.Results["systemd-analyze verify cron.service"] = system.Result{}
	h.fake.Results["systemctl daemon-reload"] = system.Result{}
	fakeEditor(t, `[Service]\nNice=5\n`)
	send(tm, "enter") // re-edit
	waitFor(t, tm, "Done in")
	wantAll(t, ctrlCView(t, tm), "SUMMARY  override for cron.service applied")
	if lockBusy(h) {
		t.Error("global lock still held after apply")
	}
	if got := readFile(t, service.OverridePath(h.root, "cron.service")); got != "[Service]\nNice=5\n" {
		t.Errorf("override after re-edit = %q", got)
	}
	if n := strings.Count(strings.Join(h.fake.Calls, "\n"), "daemon-reload"); n != 1 {
		t.Errorf("reloaded %d times, want 1", n)
	}
	log := h.actionLog()
	if strings.Count(log, "service edit cron.service: failed: ") != 2 || !strings.Contains(log, "service edit cron.service: ok") {
		t.Errorf("Task History:\n%s", log)
	}
}

// Revert asks Yes/No, then removes the override as a Task; with no
// override left, Revert is disabled.
func TestServicesRevertOverride(t *testing.T) {
	h := svcHost(t)
	h.write("/etc/systemd/system/cron.service.d/override.conf", "[Service]\nNice=1\n")
	h.fake.Results["systemctl daemon-reload"] = system.Result{}
	wantAll(t, view(openServicesWith(h, "")), "vendor unit + override (/etc/systemd/system/cron.service.d/override.conf, 2 lines)")
	tm := openServices(t, h)
	tm.Type("U")
	waitFor(t, tm, "Revert cron.service override?")
	tm.Type("y")
	waitFor(t, tm, "Done in")
	send(tm, "esc")
	tm.Type("U")
	v := ctrlCView(t, tm)
	wantAll(t, v, "vendor unit, no override")
	if strings.Contains(v, "Revert cron.service override?") {
		t.Errorf("Revert asked with no override:\n%s", v)
	}
	if _, err := os.Stat(service.OverridePath(h.root, "cron.service")); !os.IsNotExist(err) {
		t.Errorf("override still there: %v", err)
	}
	if !slices.Contains(h.fake.Calls, "systemctl daemon-reload") {
		t.Errorf("not reloaded: %q", h.fake.Calls)
	}
	if log := h.actionLog(); strings.Count(log, "\n") != 1 || !strings.Contains(log, "service revert cron.service: ok") {
		t.Errorf("Task History:\n%s", log)
	}
}
