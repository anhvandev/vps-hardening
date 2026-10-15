package tui

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

// testHost is a scripted host for TUI tests: Results feed the fake Runner,
// files are written under a temp root.
type testHost struct {
	t    *testing.T
	root string
	fake *system.Fake
	host system.Host
}

// debianHost is a hardened ubuntu host: ufw active with three rules,
// fail2ban running, updates ran, nothing pending, no reboot needed.
func debianHost(t *testing.T) *testHost {
	h := &testHost{t: t, root: t.TempDir(),
		host: system.Host{DistroID: "ubuntu", Version: "24.04", Family: "debian", Supported: true,
			SSHUnit: "ssh", AdminGroup: "sudo", PkgManager: "apt"},
		fake: &system.Fake{Results: map[string]system.Result{
			"ufw status": {Stdout: "Status: active\n"},
			"ufw show added": {Stdout: "Added user rules (see 'ufw status' for running firewall):\n" +
				"ufw allow 22/tcp\nufw allow 80/tcp\nufw allow from 10.0.0.0/8 to any port 5432 proto tcp\n"},
			"fail2ban-client status": {Stdout: "Status\n|- Number of jail:\t1\n`- Jail list:\tsshd\n"},
			"systemctl show -p LastTriggerUSec --value apt-daily-upgrade.timer": {Stdout: "Wed 2026-10-14 06:12:03 UTC\n"},
			"apt-get -s --with-new-pkgs -o Debug::NoLocking=true upgrade":       {Stdout: "Reading package lists...\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"},
			"df -h -P /": {Stdout: "Filesystem      Size  Used Avail Capacity Mounted on\n/dev/vda1        20G  4.1G   15G      22% /\n"},
			"sshd -T":    {Stdout: "port 22\npasswordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\npermitrootlogin no\n"},
		}},
	}
	h.write("/proc/meminfo", "MemTotal:        4194304 kB\nMemFree:          524288 kB\nMemAvailable:    3145728 kB\n")
	h.write("/etc/ssh/ssh_host_ed25519_key", "k")
	h.write("/etc/ssh/sshd_config.d/00-vpsctl.conf", "# Managed by vpsctl - do not edit by hand.\nPort 22\n"+
		"PasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nPermitRootLogin no\n")
	return h
}

// unharden leaves only Stage A live: SSH on 2222, password and root login still on.
func (h *testHost) unharden() {
	h.write("/etc/ssh/sshd_config.d/00-vpsctl.conf", "# Managed by vpsctl - do not edit by hand.\nPort 2222\n")
	h.fake.Results["sshd -T"] = system.Result{Stdout: "port 2222\npasswordauthentication yes\nkbdinteractiveauthentication no\npubkeyauthentication yes\npermitrootlogin yes\n"}
}

func (h *testHost) write(p, s string) {
	h.t.Helper()
	full := filepath.Join(h.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(s), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

// start opens the TUI on h in a fixed-size virtual terminal.
func start(h *testHost) *teatest.TestModel {
	m := New(harden.NewMachine(h.fake, h.host, h.root, io.Discard), time.Now())
	return teatest.NewTestModel(h.t, m, teatest.WithInitialTermSize(120, 40))
}

// waitFor blocks until the rendered output contains s.
func waitFor(t *testing.T, tm *teatest.TestModel, s string) {
	t.Helper()
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		return bytes.Contains([]byte(ansi.Strip(string(b))), []byte(s))
	}, teatest.WithDuration(3*time.Second))
}

// quitView presses q and returns the last frame as plain text.
func quitView(t *testing.T, tm *teatest.TestModel) string {
	t.Helper()
	tm.Type("q")
	return ansi.Strip(tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second)).View().Content)
}

func wantAll(t *testing.T, view string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(view, w) {
			t.Errorf("view missing %q:\n%s", w, view)
		}
	}
}

func TestOverviewOnHardenedHost(t *testing.T) {
	tm := start(debianHost(t))
	waitFor(t, tm, "Uptime")
	v := quitView(t, tm)
	wantAll(t, v,
		"SSH         ● key-only · :22", "Firewall    ● ufw · 3 rules",
		"● 0 security · 0 other pending", "last auto-run", "● no reboot required",
		"Disk /      ▇▇▁▁▁▁▁▁▁▁  4.1G/20G  22%",
		"RAM         ▇▇▇▁▁▁▁▁▁▁  1.0/4.0 GiB",
	)
	if strings.Contains(strings.ToLower(v), "not hardened") {
		t.Errorf("hardened host shows the banner:\n%s", v)
	}
}

func TestBannerOnUnhardenedHost(t *testing.T) {
	h := debianHost(t)
	h.unharden()
	tm := start(h)
	waitFor(t, tm, "Uptime")
	v := quitView(t, tm)
	wantAll(t, v, "NOT HARDENED", "Overview", "SSH         ✗ not key-only")
}

// The Overview leaves ?, m and tab to the shell, and q quits from it like
// from any screen that isn't typing.
func TestShellKeysOnOverview(t *testing.T) {
	tm := start(debianHost(t))
	waitFor(t, tm, "Uptime")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // focus the Overview
	tm.Type("?")
	waitFor(t, tm, "Shift+drag to select text")
	tm.Type(" ") // closes the help
	tm.Type("q")
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

func TestQuitFromAScreen(t *testing.T) {
	tm := openFirewall(t, debianHost(t))
	tm.Type("q")
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

func TestQuit(t *testing.T) {
	tm := start(debianHost(t))
	waitFor(t, tm, "Overview")
	tm.Type("q")
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

// Reopening the Overview reads the host again: rules added by hand show up.
func TestOverviewReadsLiveOnEachOpen(t *testing.T) {
	h := debianHost(t)
	tm := start(h)
	waitFor(t, tm, "Uptime")
	var rules strings.Builder
	for p := 1001; p <= 1012; p++ {
		fmt.Fprintf(&rules, "ufw allow %d/tcp\n", p)
	}
	h.fake.Results["ufw show added"] = system.Result{Stdout: rules.String()}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // reopen the Overview
	waitFor(t, tm, "12 rules")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape}) // back to the menu
	waitFor(t, tm, "q quit")
	v := quitView(t, tm)
	wantAll(t, v, "ufw · 12 rules")
}

// menuTo is the keys that move the sidebar cursor from Overview (where the
// TUI opens) to title.
func menuTo(title string) string {
	n := slices.Index(items(), title) - slices.Index(items(), "Overview")
	if n < 0 {
		return strings.Repeat("k", -n)
	}
	return strings.Repeat("j", n)
}

func TestUsersScreenListsManagedUsers(t *testing.T) {
	t.Setenv("SUDO_USER", "alice")
	h := debianHost(t)
	h.fake.Results["getent passwd"] = system.Result{Stdout: "root:x:0:0:root:/root:/bin/bash\n" +
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"alice:x:1000:1000::/home/alice:/bin/bash\n" +
		"bob:x:1001:1001::/home/bob:/usr/sbin/nologin\n"}
	h.fake.Results["getent group"] = system.Result{Stdout: "sudo:x:27:\n"}
	h.fake.Results["getent shadow"] = system.Result{Stdout: "alice:!:19000:0:99999:7:::\nbob:!:19000:0:99999:7:::\n"}
	h.write("/etc/sudoers.d/99-vpsctl-alice", "alice ALL=(ALL:ALL) NOPASSWD: ALL\n")
	h.write("/home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAA a\nssh-ed25519 BBBB b\n")

	tm := start(h)
	waitFor(t, tm, "RAM")
	tm.Type(menuTo("Users"))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "STATE")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape})
	waitFor(t, tm, "q quit")
	v := quitView(t, tm)
	wantAll(t, v, "USER", "SUDO", "KEYS", "STATE", "2 Managed Users · 1 with sudo",
		"alice (you)  ●     2     ● active  —           ◆",
		"bob          ·     0     ⚠ locked")
	if strings.Contains(v, "daemon") {
		t.Errorf("system account shown:\n%s", v)
	}
}

func TestOverviewOnRhelHost(t *testing.T) {
	h := &testHost{t: t, root: t.TempDir(),
		host: system.Host{DistroID: "rocky", Version: "9.4", Family: "rhel", Supported: true,
			SSHUnit: "sshd", AdminGroup: "wheel", PkgManager: "dnf"},
		fake: &system.Fake{Results: map[string]system.Result{
			"firewall-cmd --state":                                          {Stdout: "running\n"},
			"firewall-cmd --permanent --list-ports":                         {Stdout: "8080/tcp 6000-6100/udp\n"},
			"firewall-cmd --permanent --list-services":                      {Stdout: "ssh\n"},
			"firewall-cmd --permanent --list-rich-rules":                    {},
			"fail2ban-client status":                                        {Code: 255, Stderr: "Failed to access socket path"},
			"systemctl show -p LastTriggerUSec --value dnf-automatic.timer": {Stdout: "n/a\n"},
			"dnf -q -C check-update":                                        {Code: 100, Stdout: "\nkernel.x86_64   5.14.0-503   baseos\nopenssl.x86_64  1:3.2.2-6.el9   baseos\n"},
			"dnf -q -C updateinfo list --security":                          {Stdout: "RHSA-2024:1234 Important/Sec. openssl-1:3.2.2-6.el9.x86_64\n"},
			"needs-restarting -r":                                           {Code: 1, Stdout: "Reboot is required\n"},
			"df -h -P /":                                                    {Stdout: "Filesystem Size Used Avail Capacity Mounted on\n/dev/sda1 50G 10G 40G 20% /\n"},
		}},
	}
	h.write("/proc/meminfo", "MemTotal: 2097152 kB\nMemAvailable: 1048576 kB\n")
	tm := start(h)
	waitFor(t, tm, "Uptime")
	v := quitView(t, tm)
	wantAll(t, v, "Firewall    ● firewalld · 3 rules",
		"⚠ 1 security · 1 other pending", "last auto-run never", "⚠ reboot required",
		"10G/50G  20%", "1.0/2.0 GiB", "NOT HARDENED")
}
