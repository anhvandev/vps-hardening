package tui

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/anhvandev/vpsctl/internal/system"
)

const loginsQuery = "journalctl --no-pager -q -o json --since=-%s SYSLOG_IDENTIFIER=sshd + SYSLOG_IDENTIFIER=sshd-session"

// journalLine is one sshd journal entry (JSON export) at unix second ts.
func journalLine(ts int64, pid, msg string) string {
	return `{"__REALTIME_TIMESTAMP":"` + strconv.FormatInt(ts*1e6, 10) + `","_PID":"` + pid +
		`","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"` + msg + `"}` + "\n"
}

// loginsHost has, in the last 24 h, the operator's own login, one other
// login and three failing connections (two from one IP); the 7 d window adds
// an older login by bob.
func loginsHost(t *testing.T) *testHost {
	h := debianHost(t)
	day := journalLine(1792050000, "10", "Accepted publickey for anh from 203.0.113.5 port 50122 ssh2: ED25519 SHA256:x") +
		journalLine(1792050100, "11", "Invalid user admin from 45.0.0.12 port 4000") +
		journalLine(1792050101, "11", "Connection closed by invalid user admin 45.0.0.12 port 4000 [preauth]") +
		journalLine(1792050200, "12", "Failed password for root from 45.0.0.12 port 4001 ssh2") +
		journalLine(1792050300, "13", "Connection closed by authenticating user root 103.0.0.7 port 5000 [preauth]") +
		journalLine(1792050400, "14", "Accepted password for ops from 198.51.100.4 port 6000 ssh2")
	h.fake.Results[strings.Replace(loginsQuery, "%s", "24h", 1)] = system.Result{Stdout: day}
	h.fake.Results[strings.Replace(loginsQuery, "%s", "168h", 1)] = system.Result{Stdout: journalLine(1791500000, "9", "Accepted publickey for bob from 192.0.2.8 port 7000 ssh2") + day}
	h.write("/proc/"+strconv.Itoa(os.Getpid())+"/environ", "SSH_CONNECTION=203.0.113.5 50122 10.0.0.2 22\x00")
	return h
}

// openLogins starts the TUI on h and opens the loaded Logins screen.
func openLogins(t *testing.T, h *testHost) *teatest.TestModel {
	t.Helper()
	tm := start(h)
	waitFor(t, tm, "Logins 24h")
	tm.Type(menuTo("Logins"))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "Top failing IPs")
	return tm
}

// closeLogins leaves the screen and quits, returning the last frame.
func closeLogins(t *testing.T, tm *teatest.TestModel) string {
	t.Helper()
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape})
	waitFor(t, tm, "q quit")
	return quitView(t, tm)
}

func TestLoginsScreen(t *testing.T) {
	tm := openLogins(t, loginsHost(t))
	tm.Type("w")
	waitFor(t, tm, "bob")
	v := closeLogins(t, tm)
	wantAll(t, v, "(●) 7d", "3 ok · 3 failed",
		time.Unix(1792050400, 0).Format("Jan 02 15:04"), "ops", "198.51.100.4",
		"anh", "203.0.113.5", "this session",
		"bob", "192.0.2.8",
		"Top failing IPs", "45.0.0.12  2", "103.0.0.7  1")
	if strings.Contains(v, "Ban") {
		t.Errorf("Logins is read-only, no ban action:\n%s", v)
	}
}

func TestLoginsDefaultsTo24h(t *testing.T) {
	v := closeLogins(t, openLogins(t, loginsHost(t)))
	wantAll(t, v, "(●) 24h", "2 ok · 3 failed", "198.51.100.4")
	if strings.Contains(v, "bob") {
		t.Errorf("24h window shows a 7 d login:\n%s", v)
	}
}

func TestOverviewLoginsLine(t *testing.T) {
	tm := start(loginsHost(t))
	waitFor(t, tm, "Logins 24h")
	wantAll(t, quitView(t, tm), "Logins 24h", "2 ok · 3 failed")
}
