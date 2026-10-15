package service_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/anhvandev/vpsctl/internal/service"
	"github.com/anhvandev/vpsctl/internal/system"
)

const (
	listUnits     = "systemctl list-units --type=service --all --plain --no-legend --no-pager"
	listUnitFiles = "systemctl list-unit-files --type=service --plain --no-legend --no-pager"
)

func TestListMergesLiveStateAndUnitFiles(t *testing.T) {
	r := &system.Fake{Results: map[string]system.Result{
		listUnits: {Stdout: "cron.service       loaded    active   running Regular background program processing daemon\n" +
			"gone.service       not-found inactive dead    gone.service\n" +
			"nginx.service      loaded    failed   failed  A high performance web server\n" +
			"systemd-journald.service loaded active running Journal Service\n"},
		listUnitFiles: {Stdout: "cron.service enabled enabled\n" +
			"getty@.service enabled enabled\n" +
			"nginx.service disabled enabled\n" +
			"redis.service enabled enabled\n" +
			"systemd-journald.service static -\n"},
	}}
	got, err := service.List(r)
	if err != nil {
		t.Fatal(err)
	}
	want := []service.Service{
		{Name: "cron.service", Active: "active", Sub: "running", Enabled: "enabled", Description: "Regular background program processing daemon"},
		{Name: "nginx.service", Active: "failed", Sub: "failed", Enabled: "disabled", Description: "A high performance web server"},
		{Name: "redis.service", Active: "inactive", Sub: "dead", Enabled: "enabled"},
		{Name: "systemd-journald.service", Active: "active", Sub: "running", Enabled: "static", Description: "Journal Service"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("List =\n%+v\nwant\n%+v", got, want)
	}
}

func TestDoRunsSystemctl(t *testing.T) {
	r := &system.Fake{Results: map[string]system.Result{
		"systemctl restart nginx.service": {},
		"systemctl start bad.service":     {Code: 1, Stderr: "Job for bad.service failed.\n"},
	}}
	if err := service.Do(r, "restart", "nginx.service"); err != nil {
		t.Errorf("restart: %v", err)
	}
	err := service.Do(r, "start", "bad.service")
	if err == nil || !strings.Contains(err.Error(), "Job for bad.service failed.") {
		t.Errorf("start bad: %v", err)
	}
}

// Every caller gets the Protected Unit rule: a refused action runs nothing.
func TestDoRefusesProtectedUnits(t *testing.T) {
	r := &system.Fake{}
	for _, a := range [][2]string{{"stop", "ssh.service"}, {"restart", "sshd.service"}, {"disable", "ufw.service"}} {
		err := service.Do(r, a[0], a[1])
		if err == nil || !strings.HasPrefix(err.Error(), "refused: ") {
			t.Errorf("%s %s: %v", a[0], a[1], err)
		}
	}
	if len(r.Calls) != 0 {
		t.Errorf("ran %q", r.Calls)
	}
}

func TestListFailsWhenSystemctlFails(t *testing.T) {
	r := &system.Fake{Results: map[string]system.Result{
		listUnits: {Code: 1, Stderr: "Failed to connect to bus"},
	}}
	if _, err := service.List(r); err == nil {
		t.Error("want error")
	}
}
