package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/system"
)

// hardenedHost is debianHost with every Hardening Step in effect: Admin
// User anh with one key and vpsctl's sudo rule, ubuntu locked, cloud-init
// blocked, unattended upgrades and the sysctl values live.
func hardenedHost(t *testing.T) *testHost {
	h := debianHost(t)
	for k, v := range map[string]string{
		"getent passwd":               "root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000::/home/ubuntu:/usr/sbin/nologin\nanh:x:1001:1001::/home/anh:/bin/bash\n",
		"getent group":                "sudo:x:27:\n",
		"getent shadow":               "ubuntu:!$6$x:19000:0:99999:7:::\nanh:!:19000:0:99999:7:::\n",
		"dpkg -s unattended-upgrades": "Status: install ok installed\n",
	} {
		h.fake.Results[k] = system.Result{Stdout: v}
	}
	for p, s := range map[string]string{
		"/etc/sudoers.d/99-vpsctl-anh":                        "anh ALL=(ALL) NOPASSWD:ALL\n",
		"/home/anh/.ssh/authorized_keys":                      "ssh-ed25519 AAAA anh\n",
		"/etc/cloud/cloud.cfg.d/99-vpsctl.cfg":                "users: []\n",
		"/etc/apt/apt.conf.d/20auto-upgrades":                 "APT::Periodic::Unattended-Upgrade \"1\";\n",
		"/proc/sys/net/ipv4/conf/all/accept_redirects":        "0\n",
		"/proc/sys/net/ipv4/conf/all/send_redirects":          "0\n",
		"/proc/sys/net/ipv4/conf/default/accept_source_route": "0\n",
		"/proc/sys/net/ipv4/tcp_syncookies":                   "1\n",
		"/proc/sys/net/ipv6/conf/all/accept_redirects":        "0\n",
		"/proc/sys/kernel/kptr_restrict":                      "2\n",
	} {
		h.write(p, s)
	}
	return h
}

// openHardening opens the Hardening screen and waits for what.
func openHardening(t *testing.T, h *testHost, what string) string {
	tm := startSized(h, 120, 40)
	waitFor(t, tm, "Uptime")
	tm.Type(menuTo("Hardening"))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, what)
	return ctrlCView(t, tm)
}

func TestHardeningStatusAllDone(t *testing.T) {
	v := openHardening(t, hardenedHost(t), "sysctl hardening")
	wantAll(t, v, "● Hardening 9/9", "no Hardening Record", "STEP", "STATE")
	for _, row := range [][]string{
		{"Admin User + key", "● Done", "anh · 1 key"},
		{"Key-only SSH, no root login", "● Done"},
		{"SSH port", "● Done", "22"},
		{"Firewall on", "● Done", "ufw"},
		{"Default Cloud Users locked", "● Done", "ubuntu"},
		{"cloud-init re-injection block", "● Done"},
		{"fail2ban", "● Done", "sshd jail"},
		{"Automatic security updates", "● Done", "unattended-upgrades"},
		{"sysctl hardening", "● Done"},
	} {
		if !lineHas(v, row...) {
			t.Errorf("no row %q:\n%s", row, v)
		}
	}
	if strings.Contains(v, "Skip firewall") {
		t.Errorf("wizard on a hardened machine:\n%s", v)
	}
}

// Without a Record a step that is off is Missing, never Skipped, with no
// applied date; the badge turns yellow.
func TestHardeningStatusMissingWithoutRecord(t *testing.T) {
	h := hardenedHost(t)
	h.fake.Results["fail2ban-client status"] = system.Result{Code: 255}
	h.write("/proc/sys/kernel/kptr_restrict", "0\n")
	v := openHardening(t, h, "sysctl hardening")
	wantAll(t, v, "⚠ Hardening 7/9", "no Hardening Record")
	if !lineHas(v, "fail2ban", "⚠ Missing") || !lineHas(v, "sysctl hardening", "⚠ Missing") ||
		strings.Contains(v, "Skipped") || strings.Contains(v, "was applied") {
		t.Errorf("want fail2ban and sysctl Missing:\n%s", v)
	}
}

// The Record tells what the machine can't: when and by whom, the Admin
// User, a skipped step, and when a now-Missing step was applied. A skipped
// step doesn't count against the badge.
func TestHardeningStatusWithRecord(t *testing.T) {
	h := hardenedHost(t)
	h.fake.Results["fail2ban-client status"] = system.Result{Code: 255}
	h.write("/proc/sys/kernel/kptr_restrict", "0\n")
	h.write("/var/lib/vpsctl/hardening.json", `{"ran":"2026-10-15T01:12:00Z","by":"root","admin_user":"anh",`+
		`"skipped":["sysctl"],"applied":{"fail2ban":"2026-10-15T01:12:00Z"}}`)
	v := openHardening(t, h, "sysctl hardening")
	wantAll(t, v, "⚠ Hardening 7/8", "ran 2026-10-15 01:12 by root · Admin User anh")
	if !lineHas(v, "fail2ban", "⚠ Missing", "was applied 2026-10-15") {
		t.Errorf("fail2ban not Missing with its applied date:\n%s", v)
	}
	if !lineHas(v, "sysctl hardening", "· Skipped", "chosen at Hardening") {
		t.Errorf("sysctl not Skipped:\n%s", v)
	}
}

// Only Skipped steps missing: the badge stays green.
func TestBadgeGreenWithOnlySkippedSteps(t *testing.T) {
	h := hardenedHost(t)
	h.write("/proc/sys/kernel/kptr_restrict", "0\n")
	h.write("/var/lib/vpsctl/hardening.json", `{"ran":"2026-10-15T01:12:00Z","by":"root","admin_user":"anh","skipped":["sysctl"]}`)
	tm := startSized(h, 120, 40)
	waitFor(t, tm, "Uptime")
	wantAll(t, quitView(t, tm), "● Hardening 8/8")
}
