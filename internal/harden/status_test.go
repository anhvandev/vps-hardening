package harden

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anhvandev/vpsctl/internal/system"
)

const hardenedSSHD = "port 2222\npasswordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\npermitrootlogin no\n"

// hardenedMachine is an ubuntu host where every Hardening Step is in effect:
// Admin User anh with one key and vpsctl's sudo rule, key-only sshd on 2222,
// ufw active, ubuntu locked, cloud-init blocked, an sshd jail, unattended
// upgrades and the sysctl values live.
func hardenedMachine(t *testing.T) (*Machine, *system.Fake) {
	root := t.TempDir()
	f := &system.Fake{Results: map[string]system.Result{
		"getent passwd":               {Stdout: "root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000::/home/ubuntu:/usr/sbin/nologin\nanh:x:1001:1001::/home/anh:/bin/bash\n"},
		"getent group":                {Stdout: "sudo:x:27:\n"},
		"getent shadow":               {Stdout: "ubuntu:!$6$x:19000:0:99999:7:::\nanh:!:19000:0:99999:7:::\n"},
		"sshd -T":                     {Stdout: hardenedSSHD},
		"ufw status":                  {Stdout: "Status: active\n"},
		"fail2ban-client status":      {Stdout: "Status\n|- Number of jail:\t1\n`- Jail list:\tsshd\n"},
		"dpkg -s unattended-upgrades": {Stdout: "Status: install ok installed\n"},
	}}
	files := map[string]string{
		"/etc/ssh/ssh_host_ed25519_key":                       "k",
		"/etc/sudoers.d/99-vpsctl-anh":                        "anh ALL=(ALL) NOPASSWD:ALL\n",
		"/home/anh/.ssh/authorized_keys":                      "ssh-ed25519 AAAA anh\n",
		"/home/ubuntu/.ssh/authorized_keys":                   "",
		"/etc/cloud/cloud.cfg.d/99-vpsctl.cfg":                "users: []\n",
		"/etc/apt/apt.conf.d/20auto-upgrades":                 "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n",
		"/proc/sys/net/ipv4/conf/all/accept_redirects":        "0\n",
		"/proc/sys/net/ipv4/conf/all/send_redirects":          "0\n",
		"/proc/sys/net/ipv4/conf/default/accept_source_route": "0\n",
		"/proc/sys/net/ipv4/tcp_syncookies":                   "1\n",
		"/proc/sys/net/ipv6/conf/all/accept_redirects":        "0\n",
		"/proc/sys/kernel/kptr_restrict":                      "2\n",
	}
	for p, s := range files {
		write(t, filepath.Join(root, p), s, 0o644)
	}
	h := system.Host{DistroID: "ubuntu", Family: "debian", AdminGroup: "sudo", PkgManager: "apt"}
	return NewMachine(f, h, root, io.Discard), f
}

// states is "id=State" for every step, in order.
func states(steps []Step) string {
	var s []string
	for _, st := range steps {
		s = append(s, st.ID+"="+string(st.State))
	}
	return strings.Join(s, " ")
}

func TestStatusAllDone(t *testing.T) {
	m, _ := hardenedMachine(t)
	steps := m.Status(nil)
	want := "admin=Done ssh=Done port=Done firewall=Done cloud-users=Done cloud-init=Done fail2ban=Done updates=Done sysctl=Done"
	if got := states(steps); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	for i, d := range []string{"anh · 1 key", "", "2222", "ufw", "ubuntu", "", "sshd jail", "unattended-upgrades", ""} {
		if steps[i].Detail != d {
			t.Errorf("%s detail %q, want %q", steps[i].ID, steps[i].Detail, d)
		}
	}
}

// Each step reads Missing once its live check fails, and only that step.
func TestStatusEachStepDetectsMissing(t *testing.T) {
	for id, breakIt := range map[string]func(m *Machine, f *system.Fake){
		"admin": func(m *Machine, _ *system.Fake) { os.Remove(filepath.Join(m.Root, "/etc/sudoers.d/99-vpsctl-anh")) },
		"ssh": func(_ *Machine, f *system.Fake) {
			f.Results["sshd -T"] = system.Result{Stdout: strings.Replace(hardenedSSHD, "permitrootlogin no", "permitrootlogin yes", 1)}
		},
		"firewall": func(_ *Machine, f *system.Fake) {
			f.Results["ufw status"] = system.Result{Stdout: "Status: inactive\n"}
		},
		"cloud-users": func(m *Machine, _ *system.Fake) {
			write(t, filepath.Join(m.Root, "/home/ubuntu/.ssh/authorized_keys"), "ssh-rsa AAAA\n", 0o600)
		},
		"cloud-init": func(m *Machine, _ *system.Fake) {
			os.Remove(filepath.Join(m.Root, "/etc/cloud/cloud.cfg.d/99-vpsctl.cfg"))
		},
		"fail2ban": func(_ *Machine, f *system.Fake) { f.Results["fail2ban-client status"] = system.Result{Code: 255} },
		"updates":  func(_ *Machine, f *system.Fake) { delete(f.Results, "dpkg -s unattended-upgrades") },
		"sysctl": func(m *Machine, _ *system.Fake) {
			write(t, filepath.Join(m.Root, "/proc/sys/kernel/kptr_restrict"), "0\n", 0o644)
		},
	} {
		m, f := hardenedMachine(t)
		breakIt(m, f)
		for _, st := range m.Status(nil) {
			if want := map[bool]State{true: Missing, false: Done}[st.ID == id]; st.State != want {
				t.Errorf("%s broken: %s is %s, want %s", id, st.ID, st.State, want)
			}
		}
	}
	// sshd unreadable: both SSH steps are Missing.
	m, f := hardenedMachine(t)
	delete(f.Results, "sshd -T")
	if got := states(m.Status(nil)); !strings.Contains(got, "ssh=Missing port=Missing") {
		t.Errorf("sshd -T failing: %s", got)
	}
}

func TestStatusOnRHEL(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "/etc/dnf/automatic.conf"), "[commands]\nupgrade_type = security\napply_updates = yes\n", 0o644)
	f := &system.Fake{Results: map[string]system.Result{
		"firewall-cmd --state":                             {Stdout: "running\n"},
		"systemctl is-enabled --quiet dnf-automatic.timer": {},
	}}
	m := NewMachine(f, system.Host{Family: "rhel", PkgManager: "dnf"}, root, io.Discard)
	steps := m.Status(nil)
	if steps[3].State != Done || steps[3].Detail != "firewalld" || steps[7].State != Done || steps[7].Detail != "dnf-automatic" {
		t.Fatalf("firewall %+v, updates %+v", steps[3], steps[7])
	}
	f.Results["firewall-cmd --state"] = system.Result{Code: 252, Stdout: "not running\n"}
	write(t, filepath.Join(root, "/etc/dnf/automatic.conf"), "[commands]\napply_updates = no\n", 0o644)
	if steps = m.Status(nil); steps[3].State != Missing || steps[7].State != Missing {
		t.Fatalf("firewall %+v, updates %+v", steps[3], steps[7])
	}
}

// The Record adds what the machine can't tell: a Missing step the operator
// skipped is Skipped, one it applied says when. Live Done always wins.
func TestStatusWithRecord(t *testing.T) {
	m, f := hardenedMachine(t)
	f.Results["fail2ban-client status"] = system.Result{Code: 255}                  // was applied, now off
	write(t, filepath.Join(m.Root, "/proc/sys/kernel/kptr_restrict"), "0\n", 0o644) // skipped
	f.Results["ufw status"] = system.Result{Stdout: "Status: inactive\n"}           // never applied
	applied := time.Date(2026, 10, 15, 1, 12, 0, 0, time.UTC)
	rec := &Record{Admin: "anh", Skipped: []string{"sysctl", "updates"}, Applied: map[string]time.Time{"fail2ban": applied, "sysctl": applied}}

	steps := m.Status(rec)
	want := "admin=Done ssh=Done port=Done firewall=Missing cloud-users=Done cloud-init=Done fail2ban=Missing updates=Done sysctl=Skipped"
	if got := states(steps); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if !steps[6].Applied.Equal(applied) || !steps[3].Applied.IsZero() || !steps[8].Applied.IsZero() {
		t.Errorf("applied dates: fail2ban %v, firewall %v, sysctl %v", steps[6].Applied, steps[3].Applied, steps[8].Applied)
	}
}

// Without cloud-init there is nothing to block: Done.
func TestStatusCloudInitAbsent(t *testing.T) {
	m, _ := hardenedMachine(t)
	os.RemoveAll(filepath.Join(m.Root, "/etc/cloud"))
	if st := m.Status(nil)[5]; st.State != Done || st.Detail != "no cloud-init" {
		t.Errorf("cloud-init %+v", st)
	}
}
