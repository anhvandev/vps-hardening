package harden

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anhvandev/vpsctl/internal/system"
)

func write(t *testing.T, p, s string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func TestPreLockAssertions(t *testing.T) {
	setup := func() (*Machine, *system.Fake, string) {
		root := t.TempDir()
		f := &system.Fake{Results: map[string]system.Result{
			"sshd -T -C user=alice,host=localhost,addr=127.0.0.1": {Stdout: "port 22\npubkeyauthentication yes\n"},
			"getent passwd alice":        {Stdout: fmt.Sprintf("alice:x:%d:%d::/home/alice:/bin/bash\n", os.Getuid(), os.Getgid())},
			"sudo -u alice sudo -n true": {},
		}}
		ak := filepath.Join(root, "/home/alice/.ssh/authorized_keys")
		write(t, ak, "ssh-ed25519 AAAA vpsctl-alice\n", 0o600)
		write(t, filepath.Join(root, "/etc/ssh/ssh_host_ed25519_key"), "k", 0o600)
		return NewMachine(f, system.Host{}, root, io.Discard), f, ak
	}

	m, _, _ := setup()
	if err := m.PreLockAssertions("alice"); err != nil {
		t.Fatalf("healthy host: %v", err)
	}
	// sshd -T needs the privsep dir, which systemd removes whenever ssh.service
	// stops (e.g. a socket restart on a port change).
	if _, err := os.Stat(filepath.Join(m.Root, "/run/sshd")); err != nil {
		t.Errorf("privsep dir not ensured before sshd -T -C: %v", err)
	}

	for name, breakIt := range map[string]func(f *system.Fake, ak string){
		"pubkey off": func(f *system.Fake, _ string) {
			f.Results["sshd -T -C user=alice,host=localhost,addr=127.0.0.1"] = system.Result{Stdout: "pubkeyauthentication no\n"}
		},
		"authorized_keys 644":   func(_ *system.Fake, ak string) { os.Chmod(ak, 0o644) },
		"authorized_keys empty": func(_ *system.Fake, ak string) { os.Truncate(ak, 0) },
		"sudo asks password": func(f *system.Fake, _ string) {
			f.Results["sudo -u alice sudo -n true"] = system.Result{Code: 1, Stderr: "sudo: a password is required"}
		},
		"wrong owner": func(f *system.Fake, _ string) {
			f.Results["getent passwd alice"] = system.Result{Stdout: fmt.Sprintf("alice:x:%d:%d::/home/alice:/bin/bash\n", os.Getuid()+1, os.Getgid())}
		},
	} {
		m, f, ak := setup()
		breakIt(f, ak)
		if err := m.PreLockAssertions("alice"); err == nil {
			t.Errorf("%s: passed, want failure", name)
		}
	}
}

// Re-running harden on a host whose ignore list was edited in the TUI keeps
// the ignoreip entries: the drop-in comes out unchanged.
func TestFail2banRerunKeepsIgnoreList(t *testing.T) {
	root := t.TempDir()
	f := &system.Fake{Results: map[string]system.Result{
		"fail2ban-client --version":  {},
		"systemctl enable fail2ban":  {},
		"systemctl restart fail2ban": {},
	}}
	m := NewMachine(f, system.Host{Family: "debian", PkgManager: "apt"}, root, io.Discard)
	if err := m.Fail2ban(22); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "/etc/fail2ban/jail.d/00-vpsctl.local")
	b, _ := os.ReadFile(p)
	edited := "[DEFAULT]\nignoreip = 203.0.113.5 10.0.0.0/8\n\n" + string(b)
	write(t, p, edited, 0o644)
	if err := m.Fail2ban(22); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != edited {
		t.Errorf("re-run drop-in =\n%s\nwant\n%s", b, edited)
	}
}

func TestDnfAutoUpdatesAreSecurityOnly(t *testing.T) {
	root := t.TempDir()
	conf := filepath.Join(root, "/etc/dnf/automatic.conf")
	write(t, conf, "[commands]\nupgrade_type = default\nrandom_sleep = 0\ndownload_updates = yes\napply_updates = no\n", 0o644)
	f := &system.Fake{Results: map[string]system.Result{
		"rpm -q dnf-automatic":                       {},
		"systemctl enable --now dnf-automatic.timer": {},
	}}
	m := NewMachine(f, system.Host{Family: "rhel", PkgManager: "dnf"}, root, io.Discard)
	if err := m.AutoUpdates(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(conf)
	for _, want := range []string{"\nupgrade_type = security\n", "\napply_updates = yes\n", "\nrandom_sleep = 0\n"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("automatic.conf missing %q:\n%s", want, b)
		}
	}
}

func TestAptAutoUpdatesAreSecurityOnlyWithoutReboot(t *testing.T) {
	root := t.TempDir()
	f := &system.Fake{Results: map[string]system.Result{
		"dpkg -s unattended-upgrades":                                    {},
		"systemctl enable --now apt-daily.timer apt-daily-upgrade.timer": {},
	}}
	m := NewMachine(f, system.Host{Family: "debian", PkgManager: "apt"}, root, io.Discard)
	if err := m.AutoUpdates(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(root, "/etc/apt/apt.conf.d/52vpsctl-unattended-upgrades"))
	for _, want := range []string{"#clear Unattended-Upgrade::Origins-Pattern;", "-security", `Unattended-Upgrade::Automatic-Reboot "false";`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("unattended-upgrades override missing %q:\n%s", want, b)
		}
	}
}
