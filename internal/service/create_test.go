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

func TestSpecRendersServiceUnit(t *testing.T) {
	unit, content, err := service.Spec{
		Name: "myapp", Description: "My app", Command: "/usr/bin/node server.js", User: "alice",
		WorkingDir: "/srv/myapp", Restart: "always", Environment: "PORT=3000 NODE_ENV=production",
	}.Unit()
	if err != nil {
		t.Fatal(err)
	}
	want := "[Unit]\nDescription=My app\n\n[Service]\nExecStart=/usr/bin/node server.js\nUser=alice\n" +
		"WorkingDirectory=/srv/myapp\nRestart=always\nEnvironment=PORT=3000 NODE_ENV=production\n\n" +
		"[Install]\nWantedBy=multi-user.target\n"
	if unit != "myapp.service" || string(content) != want {
		t.Errorf("Unit = %q,\n%s", unit, content)
	}

	// Optional fields left empty are left out; a .service suffix is accepted.
	_, content, err = service.Spec{Name: "worker.service", Command: "/opt/w", User: "root", Restart: "no"}.Unit()
	want = "[Unit]\n\n[Service]\nExecStart=/opt/w\nUser=root\nRestart=no\n\n[Install]\nWantedBy=multi-user.target\n"
	if err != nil || string(content) != want {
		t.Errorf("minimal Unit = %v,\n%s", err, content)
	}
}

func TestSpecRejectsInvalidFields(t *testing.T) {
	ok := service.Spec{Name: "myapp", Command: "/opt/app", User: "alice", Restart: "on-failure"}
	for want, change := range map[string]func(*service.Spec){
		"invalid name":           func(s *service.Spec) { s.Name = "" },
		"invalid name \"my app\"": func(s *service.Spec) { s.Name = "my app" },
		"invalid name \"a@\"":     func(s *service.Spec) { s.Name = "a@" },
		"invalid name \"../x\"":   func(s *service.Spec) { s.Name = "../x" },
		"command is required":    func(s *service.Spec) { s.Command = " " },
		"user is required":       func(s *service.Spec) { s.User = "" },
		"invalid restart policy": func(s *service.Spec) { s.Restart = "sometimes" },
		"line breaks":            func(s *service.Spec) { s.Environment = "A=1\nExecStartPre=/bin/evil" },
	} {
		s := ok
		change(&s)
		if _, _, err := s.Unit(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v", want, err)
		}
	}
	if _, _, err := ok.Unit(); err != nil {
		t.Errorf("valid spec: %v", err)
	}
}

const unitFile = "[Service]\nExecStart=/opt/app\n"

func TestCreateWritesVerifiesAndReloads(t *testing.T) {
	root := t.TempDir()
	r := &system.Fake{Results: map[string]system.Result{
		"systemctl show -p LoadState --value myapp.service": {Stdout: "not-found\n"},
		"systemd-analyze verify myapp.service":              {},
		"systemctl daemon-reload":                           {},
	}}
	if err := service.Create(r, root, "myapp.service", []byte(unitFile)); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "etc/systemd/system/myapp.service")); string(b) != unitFile {
		t.Errorf("unit = %q", b)
	}
	if !slices.Contains(r.Calls, "systemctl daemon-reload") {
		t.Errorf("not reloaded: %q", r.Calls)
	}
}

// A name systemd already knows (loaded, masked, from any unit directory) or a
// file already at the path is refused before anything is written.
func TestCreateRefusesExistingUnit(t *testing.T) {
	root := t.TempDir()
	r := &system.Fake{Results: map[string]system.Result{
		"systemctl show -p LoadState --value nginx.service": {Stdout: "loaded\n"},
		"systemctl show -p LoadState --value stale.service": {Stdout: "not-found\n"},
	}}
	err := service.Create(r, root, "nginx.service", []byte(unitFile))
	if err == nil || !strings.Contains(err.Error(), "nginx.service already exists") {
		t.Errorf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/systemd/system/nginx.service")); !os.IsNotExist(err) {
		t.Errorf("unit written: %v", err)
	}

	path := service.UnitPath(root, "stale.service")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := service.Create(r, root, "stale.service", []byte(unitFile)); err == nil || !strings.Contains(err.Error(), "stale.service already exists") {
		t.Errorf("err = %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "keep\n" {
		t.Errorf("existing file overwritten: %q", b)
	}
	if err := service.Create(r, root, "../evil.service", []byte(unitFile)); err == nil {
		t.Error("path in unit name accepted")
	}
}

// A unit that fails verify leaves nothing behind and systemd is not reloaded.
func TestCreateLeavesNoUnitOnVerifyFailure(t *testing.T) {
	root := t.TempDir()
	r := &system.Fake{Results: map[string]system.Result{
		"systemctl show -p LoadState --value myapp.service": {Stdout: "not-found\n"},
		"systemd-analyze verify myapp.service":              {Code: 1, Stderr: "myapp.service: Executable path is not absolute\n"},
	}}
	err := service.Create(r, root, "myapp.service", []byte(unitFile))
	if err == nil || !strings.Contains(err.Error(), "Executable path is not absolute") {
		t.Errorf("err = %v", err)
	}
	if _, err := os.Stat(service.UnitPath(root, "myapp.service")); !os.IsNotExist(err) {
		t.Errorf("unit left behind: %v", err)
	}
	if slices.Contains(r.Calls, "systemctl daemon-reload") {
		t.Error("reloaded after a failed verify")
	}
}
