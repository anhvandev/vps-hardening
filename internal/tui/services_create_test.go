package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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

func TestServicesCreateFromForm(t *testing.T) {
	h := createHost(t)
	s := openServicesWith(h, "n")
	wantAll(t, view(s), "New Service", "alice", "on-failure")

	s = keys(s, "myapp", "down", "My app", "down", "/opt/app/run", "enter")
	wantAll(t, view(s), "created myapp.service", "enable and start myapp.service now? y/n")
	want := "[Unit]\nDescription=My app\n\n[Service]\nExecStart=/opt/app/run\nUser=alice\nRestart=on-failure\n\n" +
		"[Install]\nWantedBy=multi-user.target\n"
	if got := readFile(t, service.UnitPath(h.root, "myapp.service")); got != want {
		t.Errorf("unit = %q", got)
	}

	h.fake.Results["systemctl enable myapp.service"] = system.Result{}
	h.fake.Results["systemctl start myapp.service"] = system.Result{}
	s = keys(s, "y")
	wantAll(t, view(s), "enabled and started myapp.service")
	log := h.actionLog()
	for _, w := range []string{"service create myapp.service: ok", "service enable+start myapp.service: ok"} {
		if !strings.Contains(log, w) {
			t.Errorf("action log missing %q:\n%s", w, log)
		}
	}
}

// With no Managed User the user stays empty: root runs a Service only when
// typed in. Declining the offer leaves the Service created but stopped.
func TestServicesCreateAsRootOnlyExplicitly(t *testing.T) {
	h := createHost(t)
	h.fake.Results["getent passwd"] = system.Result{Stdout: "root:x:0:0:root:/root:/bin/bash\n"}
	s := keys(openServicesWith(h, "n"), "myapp", "down", "down", "/opt/app/run", "enter")
	wantAll(t, view(s), "New Service", "user is required")
	if log := h.actionLog(); log != "" {
		t.Errorf("rejected form logged:\n%s", log)
	}

	s = keys(s, "down", "root", "enter")
	wantAll(t, view(s), "created myapp.service")
	if got := readFile(t, service.UnitPath(h.root, "myapp.service")); !strings.Contains(got, "User=root\n") {
		t.Errorf("unit = %q", got)
	}
	s = keys(s, "n")
	wantAll(t, view(s), "created myapp.service, not enabled or started")
	for _, c := range h.fake.Calls {
		if strings.HasPrefix(c, "systemctl enable") || strings.HasPrefix(c, "systemctl start") {
			t.Errorf("ran %q after declining", c)
		}
	}
}

// A name already taken is refused with the form kept open for a new name.
func TestServicesCreateRefusesExistingName(t *testing.T) {
	h := createHost(t)
	h.fake.Results["systemctl show -p LoadState --value nginx.service"] = system.Result{Stdout: "loaded\n"}
	s := keys(openServicesWith(h, "n"), "nginx", "down", "down", "/opt/app/run", "enter")
	wantAll(t, view(s), "New Service", "nginx.service already exists")
	if log := h.actionLog(); !strings.Contains(log, "service create nginx.service: failed: nginx.service already exists") {
		t.Errorf("action log:\n%s", log)
	}

	s = keys(s, "up", "up", "backspace", "backspace", "backspace", "backspace", "backspace", "myapp", "enter")
	wantAll(t, view(s), "created myapp.service")
}

func TestServicesCreateRefusedWhileLocked(t *testing.T) {
	h := createHost(t)
	lk, err := actionlog.Lock(filepath.Join(h.root, actionlog.LockPath))
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Close()
	s := keys(openServicesWith(h, "n"), "myapp", "down", "down", "/opt/app/run", "enter")
	wantAll(t, view(s), "New Service", "locked by ")
	if _, err := os.Stat(service.UnitPath(h.root, "myapp.service")); !os.IsNotExist(err) {
		t.Errorf("unit written while locked: %v", err)
	}
}

// A failed start shows the error and leaves the new Service selected, so l
// opens its journal.
func TestServicesCreateStartFailurePointsToJournal(t *testing.T) {
	h := createHost(t)
	s := keys(openServicesWith(h, "n"), "myapp", "down", "down", "/opt/app/run", "enter")
	h.fake.Results["systemctl list-units --type=service --all --plain --no-legend --no-pager"] = system.Result{Stdout: "" +
		"cron.service  loaded active running Regular background program processing daemon\n" +
		"myapp.service loaded failed failed\n"}
	h.fake.Results["systemctl enable myapp.service"] = system.Result{}
	h.fake.Results["systemctl start myapp.service"] = system.Result{Code: 1, Stderr: "Job for myapp.service failed.\n"}
	h.fake.Results["journalctl -u myapp.service -n 200 --no-pager"] = system.Result{Stdout: "myapp: cannot bind :80\n"}
	s = keys(s, "y")
	wantAll(t, view(s), "Job for myapp.service failed.", "l opens myapp.service's journal")
	if log := h.actionLog(); !strings.Contains(log, "service enable+start myapp.service: failed: ") {
		t.Errorf("action log:\n%s", log)
	}
	wantAll(t, view(keys(s, "l")), "Journal: myapp.service", "cannot bind :80")
}
