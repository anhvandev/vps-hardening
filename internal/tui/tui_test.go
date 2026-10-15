package tui

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
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
			"apt-get -s -o Debug::NoLocking=true upgrade":                       {Stdout: "Reading package lists...\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"},
			"df -h -P /": {Stdout: "Filesystem      Size  Used Avail Capacity Mounted on\n/dev/vda1        20G  4.1G   15G      22% /\n"},
		}},
	}
	h.write("/proc/meminfo", "MemTotal:        4194304 kB\nMemFree:          524288 kB\nMemAvailable:    3145728 kB\n")
	h.write("/etc/ssh/sshd_config.d/00-vpsctl.conf", "# Managed by vpsctl - do not edit by hand.\nPort 22\n"+
		"PasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nPermitRootLogin no\n")
	return h
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
	m := New(harden.NewMachine(h.fake, h.host, h.root, io.Discard))
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
	waitFor(t, tm, "5432/tcp")
	v := quitView(t, tm)
	wantAll(t, v,
		"Firewall", "active", "22/tcp", "80/tcp", "5432/tcp from 10.0.0.0/8",
		"fail2ban", "sshd",
		"Wed 2026-10-14 06:12:03 UTC", "0 pending", "no reboot required",
		"4.1G used of 20G (22%)",
		"1.0 GiB used of 4.0 GiB",
	)
	if strings.Contains(strings.ToLower(v), "not hardened") {
		t.Errorf("hardened host shows the banner:\n%s", v)
	}
}

func TestBannerOnUnhardenedHost(t *testing.T) {
	h := debianHost(t)
	// Stage A only: the port is ours, auth hardening is not live yet.
	h.write("/etc/ssh/sshd_config.d/00-vpsctl.conf", "# Managed by vpsctl - do not edit by hand.\nPort 2222\n")
	tm := start(h)
	waitFor(t, tm, "5432/tcp")
	v := quitView(t, tm)
	wantAll(t, v, "NOT HARDENED", "Overview", "22/tcp")
}

func TestQuit(t *testing.T) {
	tm := start(debianHost(t))
	waitFor(t, tm, "Overview")
	tm.Type("q")
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

func TestOverviewShowsMissingPiecesAsState(t *testing.T) {
	h := debianHost(t)
	h.fake.Results["ufw status"] = system.Result{Stdout: "Status: inactive\n"}
	delete(h.fake.Results, "fail2ban-client status") // not installed
	tm := start(h)
	waitFor(t, tm, "RAM")
	v := quitView(t, tm)
	wantAll(t, v, "Firewall   inactive", "80/tcp", "fail2ban   not installed")
}

// Reopening the Overview reads the host again: a rule added by hand shows up.
func TestOverviewReadsLiveOnEachOpen(t *testing.T) {
	h := debianHost(t)
	tm := start(h)
	waitFor(t, tm, "5432/tcp")
	h.fake.Results["ufw show added"] = system.Result{Stdout: "ufw allow 22/tcp\nufw allow 443/tcp\n"}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // reopen the Overview
	waitFor(t, tm, "443/tcp")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape}) // back to the menu
	waitFor(t, tm, "q quit")
	v := quitView(t, tm)
	wantAll(t, v, "443/tcp")
}

func TestUnbuiltModulesMarkedComingSoon(t *testing.T) {
	tm := start(debianHost(t))
	waitFor(t, tm, "RAM")
	v := quitView(t, tm)
	for _, title := range menu {
		if _, built := screens[title]; !built {
			wantAll(t, v, title+" (coming soon)")
		}
	}
}

func TestOverviewOnRhelHost(t *testing.T) {
	h := &testHost{t: t, root: t.TempDir(),
		host: system.Host{DistroID: "rocky", Version: "9.4", Family: "rhel", Supported: true,
			SSHUnit: "sshd", AdminGroup: "wheel", PkgManager: "dnf"},
		fake: &system.Fake{Results: map[string]system.Result{
			"firewall-cmd --state":                                          {Stdout: "running\n"},
			"firewall-cmd --permanent --list-ports":                         {Stdout: "8080/tcp 6000-6100/udp\n"},
			"firewall-cmd --permanent --list-services":                      {Stdout: "ssh dhcpv6-client\n"},
			"firewall-cmd --permanent --list-rich-rules":                    {},
			"fail2ban-client status":                                        {Code: 255, Stderr: "Failed to access socket path"},
			"systemctl show -p LastTriggerUSec --value dnf-automatic.timer": {Stdout: "n/a\n"},
			"dnf -q -C check-update":                                        {Code: 100, Stdout: "\nkernel.x86_64   5.14.0-503   baseos\nopenssl.x86_64  3.2.2-6   baseos\n"},
			"needs-restarting -r":                                           {Code: 1, Stdout: "Reboot is required\n"},
			"df -h -P /":                                                    {Stdout: "Filesystem Size Used Avail Capacity Mounted on\n/dev/sda1 50G 10G 40G 20% /\n"},
		}},
	}
	h.write("/proc/meminfo", "MemTotal: 2097152 kB\nMemAvailable: 1048576 kB\n")
	tm := start(h)
	waitFor(t, tm, "RAM")
	v := quitView(t, tm)
	wantAll(t, v, "Firewall   active", "8080/tcp", "6000-6100/udp", "22/tcp",
		"fail2ban   inactive", "last run never · 2 pending · REBOOT REQUIRED",
		"10G used of 50G (20%)", "1.0 GiB used of 2.0 GiB", "NOT HARDENED")
}
