package service_test

import (
	"os"
	"path/filepath"
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

func TestApplyVerifiesThenReloads(t *testing.T) {
	root := t.TempDir()
	r := &system.Fake{Results: map[string]system.Result{
		"systemd-analyze verify nginx.service": {},
		"systemctl daemon-reload":              {},
	}}
	path := service.OverridePath(root, "nginx.service")
	if err := service.Apply(r, path, "nginx.service", []byte("[Service]\nNice=5\n")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "etc/systemd/system/nginx.service.d/override.conf")); string(b) != "[Service]\nNice=5\n" {
		t.Errorf("override = %q", b)
	}
	if want := []string{"systemd-analyze verify nginx.service", "systemctl daemon-reload"}; !slices.Equal(r.Calls, want) {
		t.Errorf("ran %q, want %q", r.Calls, want)
	}
}

// A failed verify applies nothing: the previous override (or none) stays and
// systemd is not reloaded.
func TestApplyKeepsPreviousOnVerifyFailure(t *testing.T) {
	root := t.TempDir()
	r := &system.Fake{Results: map[string]system.Result{
		"systemd-analyze verify nginx.service": {Code: 1, Stderr: "override.conf:2: Unknown key name 'Nise'\n"},
	}}
	path := service.OverridePath(root, "nginx.service")
	err := service.Apply(r, path, "nginx.service", []byte("[Service]\nNise=5\n"))
	if err == nil || !strings.Contains(err.Error(), "Unknown key name 'Nise'") {
		t.Errorf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Errorf("left %s behind: %v", filepath.Dir(path), err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[Service]\nNice=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := service.Apply(r, path, "nginx.service", []byte("[Service]\nNise=5\n")); err == nil {
		t.Error("want error")
	}
	if b, _ := os.ReadFile(path); string(b) != "[Service]\nNice=1\n" {
		t.Errorf("override = %q, want previous", b)
	}
	if slices.Contains(r.Calls, "systemctl daemon-reload") {
		t.Error("reloaded after a failed verify")
	}
}

func TestApplyAndRevertRefuseProtectedUnits(t *testing.T) {
	root := t.TempDir()
	r := &system.Fake{}
	path := service.OverridePath(root, "ssh.service")
	err := service.Apply(r, path, "ssh.service", []byte("[Service]\n"))
	if err == nil || !strings.HasPrefix(err.Error(), "refused: ") {
		t.Errorf("Apply: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("wrote %s: %v", path, err)
	}
	if err := service.Revert(r, root, "ufw.service"); err == nil || !strings.HasPrefix(err.Error(), "refused: ") {
		t.Errorf("Revert: %v", err)
	}
	if len(r.Calls) != 0 {
		t.Errorf("ran %q", r.Calls)
	}
}

func TestRevertRemovesOverrideAndReloads(t *testing.T) {
	root := t.TempDir()
	r := &system.Fake{Results: map[string]system.Result{"systemctl daemon-reload": {}}}
	path := service.OverridePath(root, "nginx.service")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[Service]\nNice=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := service.Revert(r, root, "nginx.service"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Errorf("override left: %v", err)
	}
	if !slices.Equal(r.Calls, []string{"systemctl daemon-reload"}) {
		t.Errorf("ran %q", r.Calls)
	}
	if err := service.Revert(r, root, "nginx.service"); err == nil || !strings.Contains(err.Error(), "nginx.service has no override") {
		t.Errorf("second Revert: %v", err)
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
