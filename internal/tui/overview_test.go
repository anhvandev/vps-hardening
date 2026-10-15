package tui

import (
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/system"
)

// overviewHost is svcHost (nginx failed) with a Timer whose Service failed,
// security and other updates pending, a reboot waiting and the CPU, load and
// uptime readable.
func overviewHost(t *testing.T) *testHost {
	h := svcHost(t)
	h.fake.Results["systemctl list-units --type=service --all --plain --no-legend --no-pager"] = system.Result{Stdout: "" +
		"backup.service  loaded failed   failed  Nightly backup\n" +
		"cron.service    loaded active   running Regular background program processing daemon\n" +
		"nginx.service   loaded failed   failed  A high performance web server\n" +
		"ssh.service     loaded active   running OpenBSD Secure Shell server\n"}
	h.fake.Results["systemctl list-timers --all --plain --no-legend --no-pager"] = system.Result{Stdout: "" +
		"Thu 2026-10-15 03:00:00 UTC 5h left Wed 2026-10-14 03:00:00 UTC 18h ago backup.timer backup.service\n"}
	h.fake.Results["systemctl list-unit-files --type=timer --plain --no-legend --no-pager"] = system.Result{Stdout: "backup.timer enabled enabled\n"}
	h.fake.Results["apt-get -s --with-new-pkgs -o Debug::NoLocking=true upgrade"] = system.Result{Stdout: "" +
		"Inst openssl [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-security [amd64])\n" +
		"Inst vim [2:9.1.0016-1ubuntu7.3] (2:9.1.0016-1ubuntu7.4 Ubuntu:24.04/noble-updates [amd64])\n" +
		"Inst curl [8.5.0-2ubuntu10.4] (8.5.0-2ubuntu10.5 Ubuntu:24.04/noble-updates [amd64])\n"}
	h.write("/var/run/reboot-required", "")
	h.write("/proc/stat", "cpu  300 0 0 700 0 0 0 0 0 0\ncpu0 300 0 0 700 0 0 0 0 0 0\n")
	h.write("/proc/loadavg", "0.42 0.30 0.20 1/123 4567\n")
	h.write("/proc/uptime", "1051200.50 2000000.00\n")
	return h
}

func TestOverviewCards(t *testing.T) {
	tm := start(overviewHost(t))
	waitFor(t, tm, "Uptime")
	v := quitView(t, tm)
	wantAll(t, v,
		"Security", "Resources", "Updates", "Services", "refreshed 0s ago",
		"Hardening", "SSH         ● key-only · :22", "Firewall    ● ufw · 3 rules",
		"CPU         ▇▇▇▁▁▁▁▁▁▁  30%  load 0.42", "RAM         ▇▇▇▁▁▁▁▁▁▁  1.0/4.0 GiB",
		"Disk /      ▇▇▁▁▁▁▁▁▁▁  4.1G/20G  22%", "Uptime      12d 4h",
		"1 security · 2 other pending", "last auto-run", "⚠ reboot required",
		"● 2 running", "✗ failed: backup.service", "✗ failed: nginx.service", "⚠ 1 Timer missed last run")
}

// Missing pieces are states: no firewall, no fail2ban, no updates info, no
// systemd listing.
func TestOverviewMissingDataIsAState(t *testing.T) {
	h := debianHost(t)
	h.fake.Results["ufw status"] = system.Result{Stdout: "Status: inactive\n"}
	delete(h.fake.Results, "apt-get -s --with-new-pkgs -o Debug::NoLocking=true upgrade")
	delete(h.fake.Results, "fail2ban-client status")
	tm := start(h)
	waitFor(t, tm, "Uptime")
	v := quitView(t, tm)
	wantAll(t, v, "Firewall    ✗ ufw inactive", "pending updates unknown", "missing:", "Services unknown",
		"CPU         unknown", "Uptime      unknown")
}

// overviewClick is a click on screen-local cell (x, y) of the Overview at
// 120×40 (the screen starts at column 27, row 1).
func overviewClick(x, y int) tea.MouseClickMsg { return click(27+x, 1+y) }

// Clicking a failed Service opens the Services screen on it.
func TestOverviewFailedServiceOpensIt(t *testing.T) {
	tm := start(overviewHost(t))
	waitFor(t, tm, "Uptime")
	// Services card is the right one of the second row (x ≥ 46); its lines:
	// running (y 10), backup (11), nginx (12).
	tm.Send(overviewClick(50, 12))
	waitFor(t, tm, "NOTE")
	tm.Type("l") // the journal of the selected Service
	waitFor(t, tm, "Journal: nginx.service")
	ctrlCView(t, tm)
}

// Clicking the Logins line opens Logins.
func TestOverviewLoginsOpensLogins(t *testing.T) {
	tm := start(loginsHost(t))
	waitFor(t, tm, "Uptime")
	tm.Send(overviewClick(4, 7)) // Security card, fifth line
	waitFor(t, tm, "Top failing IPs")
	ctrlCView(t, tm)
}

// The shell's tick moves "refreshed Ns ago".
func TestOverviewRefreshedAgo(t *testing.T) {
	tm := start(overviewHost(t))
	waitFor(t, tm, "Uptime")
	tm.Send(tickMsg{now: time.Now().Add(2 * time.Second)})
	wantAll(t, quitView(t, tm), "refreshed 2s ago")
}

// A refresh reads the host again: CPU is measured since the last read.
func TestOverviewRefreshes(t *testing.T) {
	h := overviewHost(t)
	tm := start(h)
	waitFor(t, tm, "Uptime")
	h.write("/proc/stat", "cpu  600 0 0 900 0 0 0 0 0 0\n") // 300 of 500 since: 60%
	h.write("/proc/loadavg", "1.50 0.30 0.20 1/123 4567\n")
	h.fake.Results["systemctl list-units --type=service --all --plain --no-legend --no-pager"] = system.Result{Stdout: "" +
		"backup.service  loaded active   running Nightly backup\n" +
		"nginx.service   loaded failed   failed  A high performance web server\n" +
		"worker.service  loaded failed   failed  Queue worker\n"}
	tm.Send(refreshMsg{})
	waitFor(t, tm, "worker.service")
	v := quitView(t, tm)
	wantAll(t, v, "60%  load 1.50", "● 1 running", "✗ failed: nginx.service", "✗ failed: worker.service")
	if strings.Contains(v, "missed") {
		t.Errorf("backup ran again, its Timer still shown as missed:\n%s", v)
	}
}
