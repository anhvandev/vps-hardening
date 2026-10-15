package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/actionlog"
	"github.com/anhvandev/vpsctl/internal/service"
	"github.com/anhvandev/vpsctl/internal/system"
)

// createHost is svcHost with Managed User alice and myapp.service free to create.
func createHost(t *testing.T) *testHost {
	h := svcHost(t)
	h.fake.Results["getent passwd"] = system.Result{Stdout: "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"}
	h.fake.Results["getent group"] = system.Result{Stdout: "sudo:x:27:\n"}
	h.fake.Results["getent shadow"] = system.Result{}
	h.fake.Results["systemctl show -p LoadState --value myapp.service"] = system.Result{Stdout: "not-found\n"}
	h.fake.Results["systemd-analyze verify myapp.service"] = system.Result{}
	h.fake.Results["systemctl daemon-reload"] = system.Result{}
	return h
}

// The form creates the Service as a Task, then offers to enable and start it.
func TestServicesCreateFromForm(t *testing.T) {
	h := createHost(t)
	h.fake.Results["systemctl enable myapp.service"] = system.Result{}
	h.fake.Results["systemctl start myapp.service"] = system.Result{}
	tm := openServices(t, h)
	tm.Type("a")
	waitFor(t, tm, "New Service")
	send(tm, "myapp", "down", "My app", "down", "/opt/app/run", "enter")
	waitFor(t, tm, "Done in")
	send(tm, "enter") // close the Done card
	waitFor(t, tm, "Enable and start myapp.service now?")
	want := "[Unit]\nDescription=My app\n\n[Service]\nExecStart=/opt/app/run\nUser=alice\nRestart=on-failure\n\n" +
		"[Install]\nWantedBy=multi-user.target\n"
	if got := readFile(t, service.UnitPath(h.root, "myapp.service")); got != want {
		t.Errorf("unit = %q", got)
	}
	tm.Type("y")
	waitFor(t, tm, "Done in")
	wantAll(t, ctrlCView(t, tm), "SUMMARY  enabled and started myapp.service")
	log := h.actionLog()
	for _, w := range []string{"service create myapp.service: ok", "service enable+start myapp.service: ok"} {
		if !strings.Contains(log, w) {
			t.Errorf("Task History missing %q:\n%s", w, log)
		}
	}
}

// With no Managed User the user stays empty: root runs a Service only when
// typed in. Declining the offer leaves the Service created but stopped.
func TestServicesCreateAsRootOnlyExplicitly(t *testing.T) {
	h := createHost(t)
	h.fake.Results["getent passwd"] = system.Result{Stdout: "root:x:0:0:root:/root:/bin/bash\n"}
	tm := openServices(t, h)
	tm.Type("a")
	send(tm, "myapp", "down", "down", "/opt/app/run", "enter")
	waitFor(t, tm, "user is required")
	if log := h.actionLog(); log != "" {
		t.Errorf("rejected form logged:\n%s", log)
	}

	send(tm, "down", "root", "enter")
	waitFor(t, tm, "Done in")
	if got := readFile(t, service.UnitPath(h.root, "myapp.service")); !strings.Contains(got, "User=root\n") {
		t.Errorf("unit = %q", got)
	}
	send(tm, "enter")
	waitFor(t, tm, "Enable and start myapp.service now?")
	tm.Type("n")
	waitFor(t, tm, "created myapp.service, not enabled or started")
	ctrlCView(t, tm)
	for _, c := range h.fake.Calls {
		if strings.HasPrefix(c, "systemctl enable") || strings.HasPrefix(c, "systemctl start") {
			t.Errorf("ran %q after declining", c)
		}
	}
}

// A name already taken fails the Task with the form kept open for a new name.
func TestServicesCreateRefusesExistingName(t *testing.T) {
	h := createHost(t)
	h.fake.Results["systemctl show -p LoadState --value nginx.service"] = system.Result{Stdout: "loaded\n"}
	tm := openServices(t, h)
	tm.Type("a")
	send(tm, "nginx", "down", "down", "/opt/app/run", "enter")
	waitFor(t, tm, "nginx.service already exists")
	send(tm, "esc") // close the Failed card
	waitFor(t, tm, "New Service")
	if log := h.actionLog(); !strings.Contains(log, "service create nginx.service: failed: nginx.service already exists") {
		t.Errorf("Task History:\n%s", log)
	}

	send(tm, "up", "up", "backspace", "backspace", "backspace", "backspace", "backspace", "myapp", "enter")
	waitFor(t, tm, "Done in")
	wantAll(t, ctrlCView(t, tm), "SUMMARY  created myapp.service")
}

// Advanced opens the generated unit in $EDITOR and creates what was saved; a
// unit failing verify leaves nothing behind and esc returns to the form.
func TestServicesCreateAdvancedInEditor(t *testing.T) {
	h := createHost(t)
	h.fake.Results["systemd-analyze verify myapp.service"] = system.Result{Code: 1, Stderr: "myapp.service: Unknown key name 'Nise'\n"}
	fakeEditor(t, `[Service]\nExecStart=/opt/app/run\nNise=5\n`)
	tm := openServices(t, h)
	tm.Type("a")
	send(tm, "myapp", "down", "down", "/opt/app/run")
	tm.Send(tea.KeyPressMsg{Code: 'e', Mod: tea.ModCtrl})
	waitFor(t, tm, "Unknown key name 'Nise'")
	send(tm, "esc") // close the Failed card
	waitFor(t, tm, "enter re-edit · esc discard")
	if _, err := os.Stat(service.UnitPath(h.root, "myapp.service")); !os.IsNotExist(err) {
		t.Errorf("invalid unit left behind: %v", err)
	}
	send(tm, "esc")
	waitFor(t, tm, "discarded edit of myapp.service")

	h.fake.Results["systemd-analyze verify myapp.service"] = system.Result{}
	fakeEditor(t, `[Service]\nExecStart=/opt/app/run\nNice=5\n`)
	tm.Send(tea.KeyPressMsg{Code: 'e', Mod: tea.ModCtrl}) // the form is still filled in
	waitFor(t, tm, "Done in")
	send(tm, "enter")
	waitFor(t, tm, "Enable and start myapp.service now?")
	tm.Type("n")
	waitFor(t, tm, "not enabled or started")
	ctrlCView(t, tm)
	if got := readFile(t, service.UnitPath(h.root, "myapp.service")); got != "[Service]\nExecStart=/opt/app/run\nNice=5\n" {
		t.Errorf("unit = %q", got)
	}
	if lockBusy(h) {
		t.Error("global lock still held")
	}
	log := h.actionLog()
	if !strings.Contains(log, "service create myapp.service: failed: ") || !strings.Contains(log, "service create myapp.service: ok") {
		t.Errorf("Task History:\n%s", log)
	}
}

func TestServicesCreateRefusedWhileLocked(t *testing.T) {
	h := createHost(t)
	lk, err := actionlog.Lock(filepath.Join(h.root, actionlog.LockPath))
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Close()
	tm := openServices(t, h)
	tm.Type("a")
	send(tm, "myapp", "down", "down", "/opt/app/run", "enter")
	waitFor(t, tm, "refused: locked by ")
	wantAll(t, ctrlCView(t, tm), "New Service")
	if _, err := os.Stat(service.UnitPath(h.root, "myapp.service")); !os.IsNotExist(err) {
		t.Errorf("unit written while locked: %v", err)
	}
}

// A failed start leaves the new Service selected, so l opens its journal.
func TestServicesCreateStartFailurePointsToJournal(t *testing.T) {
	h := createHost(t)
	h.fake.Results["systemctl list-units --type=service --all --plain --no-legend --no-pager"] = system.Result{Stdout: "" +
		"cron.service  loaded active running Regular background program processing daemon\n" +
		"myapp.service loaded failed failed\n"}
	h.fake.Results["systemctl enable myapp.service"] = system.Result{}
	h.fake.Results["systemctl start myapp.service"] = system.Result{Code: 1, Stderr: "Job for myapp.service failed.\n"}
	h.fake.Results["journalctl -u myapp.service -n 200 --no-pager"] = system.Result{Stdout: "myapp: cannot bind :80\n"}
	tm := openServices(t, h)
	tm.Type("a")
	send(tm, "myapp", "down", "down", "/opt/app/run", "enter")
	waitFor(t, tm, "Done in")
	send(tm, "enter")
	waitFor(t, tm, "Enable and start myapp.service now?")
	tm.Type("y")
	waitFor(t, tm, "l opens myapp.service's journal") // under the Failed card
	send(tm, "esc")
	tm.Type("l")
	waitFor(t, tm, "cannot bind :80")
	ctrlCView(t, tm)
	if log := h.actionLog(); !strings.Contains(log, "service enable+start myapp.service: failed: ") {
		t.Errorf("Task History:\n%s", log)
	}
}
