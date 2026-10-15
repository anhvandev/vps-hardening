package tui

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

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

func TestServicesEditOverride(t *testing.T) {
	h := svcHost(t)
	h.fake.Results["systemd-analyze verify cron.service"] = system.Result{}
	h.fake.Results["systemctl daemon-reload"] = system.Result{}
	fakeEditor(t, `[Service]\nNice=5\n`)
	tm := openServices(t, h)
	tm.Type("E") // first row: cron.service
	waitFor(t, tm, "override for cron.service applied, systemd reloaded")
	closeServices(t, tm)
	if got := readFile(t, service.OverridePath(h.root, "cron.service")); got != "[Service]\nNice=5\n" {
		t.Errorf("override = %q", got)
	}
	if !slices.Contains(h.fake.Calls, "systemctl daemon-reload") {
		t.Errorf("not reloaded: %q", h.fake.Calls)
	}
	if log := h.actionLog(); strings.Count(log, "\n") != 1 || !strings.Contains(log, "service edit cron.service: ok") {
		t.Errorf("action log:\n%s", log)
	}
}

// A failed verify applies nothing: the previous override stays, systemd is not
// reloaded, and the operator can discard or re-edit.
func TestServicesEditVerifyFailure(t *testing.T) {
	h := svcHost(t)
	h.write("/etc/systemd/system/cron.service.d/override.conf", "[Service]\nNice=1\n")
	h.fake.Results["systemd-analyze verify cron.service"] = system.Result{Code: 1, Stderr: "override.conf:2: Unknown key name 'Nise'\n"}
	fakeEditor(t, `[Service]\nNise=5\n`)
	tm := openServices(t, h)
	tm.Type("E")
	waitFor(t, tm, "enter re-edit · esc discard")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape})
	waitFor(t, tm, "discarded edit of cron.service")
	if got := readFile(t, service.OverridePath(h.root, "cron.service")); got != "[Service]\nNice=1\n" {
		t.Errorf("override after discard = %q", got)
	}

	tm.Type("E")
	waitFor(t, tm, "Unknown key name 'Nise'")
	h.fake.Results["systemd-analyze verify cron.service"] = system.Result{}
	h.fake.Results["systemctl daemon-reload"] = system.Result{}
	fakeEditor(t, `[Service]\nNice=5\n`)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // re-edit
	waitFor(t, tm, "override for cron.service applied")
	closeServices(t, tm)
	if got := readFile(t, service.OverridePath(h.root, "cron.service")); got != "[Service]\nNice=5\n" {
		t.Errorf("override after re-edit = %q", got)
	}
	if n := strings.Count(strings.Join(h.fake.Calls, "\n"), "daemon-reload"); n != 1 {
		t.Errorf("reloaded %d times, want 1", n)
	}
	log := h.actionLog()
	if strings.Count(log, "service edit cron.service: failed: ") != 2 || !strings.Contains(log, "service edit cron.service: ok") {
		t.Errorf("action log:\n%s", log)
	}
}

func TestServicesRevertOverride(t *testing.T) {
	h := svcHost(t)
	h.write("/etc/systemd/system/cron.service.d/override.conf", "[Service]\nNice=1\n")
	h.fake.Results["systemctl daemon-reload"] = system.Result{}
	v := view(openServicesWith(h, "U"))
	wantAll(t, v, "reverted cron.service override, systemd reloaded")
	if _, err := os.Stat(service.OverridePath(h.root, "cron.service")); !os.IsNotExist(err) {
		t.Errorf("override still there: %v", err)
	}
	if !slices.Contains(h.fake.Calls, "systemctl daemon-reload") {
		t.Errorf("not reloaded: %q", h.fake.Calls)
	}
	wantAll(t, view(openServicesWith(h, "U")), "cron.service has no override")
	log := h.actionLog()
	if !strings.Contains(log, "service revert cron.service: ok") || !strings.Contains(log, "service revert cron.service: failed: cron.service has no override") {
		t.Errorf("action log:\n%s", log)
	}
}

func TestServicesRefusesEditingSSH(t *testing.T) {
	h := svcHost(t)
	marker := filepath.Join(t.TempDir(), "ran")
	t.Setenv("EDITOR", "touch "+marker)
	tm := openServices(t, h)
	tm.Type("jjjE") // cron, nginx, redis, ssh
	waitFor(t, tm, "refused: ssh.service is a Protected Unit (remote SSH access), cannot edit it")
	closeServices(t, tm)
	if _, err := os.Stat(marker); err == nil {
		t.Error("editor opened for a Protected Unit")
	}
	if _, err := os.Stat(filepath.Dir(service.OverridePath(h.root, "ssh.service"))); err == nil {
		t.Error("override written for a Protected Unit")
	}
}
