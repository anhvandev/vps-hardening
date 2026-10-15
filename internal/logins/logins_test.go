package logins

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/anhvandev/vpsctl/internal/system"
)

const journal24h = "journalctl --no-pager -q -o json --since=-24h SYSLOG_IDENTIFIER=sshd + SYSLOG_IDENTIFIER=sshd-session"

// at is a journal timestamp (µs since the epoch) n seconds after a fixed instant.
func at(n int) time.Time { return time.Unix(1792053898+int64(n), 0) }

// ubuntuJournal is probed ubuntu-24.04 output (ident sshd): an operator login
// and a password bot whose one connection logs three failure lines.
const ubuntuJournal = `{"_PID":"142","__REALTIME_TIMESTAMP":"1792053898000000","SYSLOG_IDENTIFIER":"sshd","_COMM":"sshd","MESSAGE":"Accepted publickey for testop from 127.0.0.1 port 38444 ssh2: ED25519 SHA256:Ymqn"}
{"__REALTIME_TIMESTAMP":"1792053908000000","MESSAGE":"Invalid user ghost from 203.0.113.9 port 58570","_PID":"150","SYSLOG_IDENTIFIER":"sshd"}
{"__REALTIME_TIMESTAMP":"1792053909000000","MESSAGE":"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.9","_PID":"150","SYSLOG_IDENTIFIER":"sshd"}
{"__REALTIME_TIMESTAMP":"1792053910000000","MESSAGE":"Failed password for invalid user ghost from 203.0.113.9 port 58570 ssh2","_PID":"150","SYSLOG_IDENTIFIER":"sshd"}
{"__REALTIME_TIMESTAMP":"1792053911000000","MESSAGE":"Connection closed by invalid user ghost 203.0.113.9 port 58570 [preauth]","_PID":"150","SYSLOG_IDENTIFIER":"sshd"}
{"__REALTIME_TIMESTAMP":"1792053912000000","MESSAGE":"Received disconnect from 198.51.100.1 port 4000:11: Bye Bye [preauth]","_PID":"151","SYSLOG_IDENTIFIER":"sshd"}
`

// rockyJournal is rocky-9 output (ident sshd-session, OpenSSH 9.9) from a
// key-only host: bots show only as preauth disconnects, here over IPv6.
const rockyJournal = `{"__REALTIME_TIMESTAMP":"1792053898000000","SYSLOG_IDENTIFIER":"sshd-session","_COMM":"sshd-session","_PID":"900","MESSAGE":"Connection closed by authenticating user root 2001:db8::1 port 22022 [preauth]","_SYSTEMD_UNIT":"sshd.service"}
{"__REALTIME_TIMESTAMP":"1792053899000000","SYSLOG_IDENTIFIER":"sshd-session","_PID":"901","MESSAGE":"Disconnected from invalid user admin 2001:db8::1 port 22023 [preauth]"}
{"__REALTIME_TIMESTAMP":"1792053900000000","SYSLOG_IDENTIFIER":"sshd-session","_PID":"902","MESSAGE":"Accepted password for ops from 192.0.2.5 port 50000 ssh2"}
{"__REALTIME_TIMESTAMP":"1792053901000000","SYSLOG_IDENTIFIER":"sshd-session","_PID":"902","MESSAGE":"pam_unix(sshd:session): session opened for user ops(uid=1000) by ops(uid=0)"}
`

func TestReadJournalOneEntryPerConnection(t *testing.T) {
	f := &system.Fake{Results: map[string]system.Result{journal24h: {Stdout: ubuntuJournal}}}
	got, err := Read(f, t.TempDir(), Day, at(100))
	if err != nil {
		t.Fatal(err)
	}
	want := []Login{
		{Time: at(10), User: "ghost", IP: "203.0.113.9", Port: "58570"},
		{Time: at(0), User: "testop", IP: "127.0.0.1", Port: "38444", OK: true},
	}
	if !slices.Equal(got, want) {
		t.Errorf("Read = %+v\nwant %+v", got, want)
	}
}

func TestReadJournalSSHDSession(t *testing.T) {
	f := &system.Fake{Results: map[string]system.Result{
		"journalctl --no-pager -q -o json --since=-168h SYSLOG_IDENTIFIER=sshd + SYSLOG_IDENTIFIER=sshd-session": {Stdout: rockyJournal},
	}}
	got, err := Read(f, t.TempDir(), Week, at(100))
	if err != nil {
		t.Fatal(err)
	}
	want := []Login{
		{Time: at(2), User: "ops", IP: "192.0.2.5", Port: "50000", OK: true},
		{Time: at(1), User: "admin", IP: "2001:db8::1", Port: "22023"},
		{Time: at(0), User: "root", IP: "2001:db8::1", Port: "22022"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("Read = %+v\nwant %+v", got, want)
	}
}

func write(t *testing.T, root, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, p), []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Without a usable journal, the syslog file is read: /var/log/secure (RHEL,
// old rsyslog: no year) and /var/log/auth.log (Debian, RFC 3339).
func TestReadFallsBackToSyslogFiles(t *testing.T) {
	now := time.Date(2026, 1, 1, 6, 0, 0, 0, time.Local)
	root := t.TempDir()
	write(t, root, "/var/log/secure", ""+
		"Dec 30 11:00:00 web sshd[10]: Accepted publickey for old from 192.0.2.1 port 1 ssh2\n"+
		"Dec 31 23:59:00 web sshd[11]: Failed password for root from 192.0.2.2 port 2 ssh2\n"+
		"Jan  1 05:00:00 web sshd[12]: Accepted password for ops from 192.0.2.3 port 3 ssh2\n"+
		"Jan  1 05:00:01 web systemd[1]: Started session.\n")
	got, err := Read(&system.Fake{}, root, Day, now)
	if err != nil {
		t.Fatal(err)
	}
	want := []Login{
		{Time: time.Date(2026, 1, 1, 5, 0, 0, 0, time.Local), User: "ops", IP: "192.0.2.3", Port: "3", OK: true},
		{Time: time.Date(2025, 12, 31, 23, 59, 0, 0, time.Local), User: "root", IP: "192.0.2.2", Port: "2"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("secure: %+v\nwant %+v", got, want)
	}

	root = t.TempDir()
	write(t, root, "/var/log/auth.log",
		"2026-01-01T02:00:00.123456+00:00 web sshd-session[20]: Invalid user x from 192.0.2.9 port 9\n")
	failing := &system.Fake{Results: map[string]system.Result{journal24h: {Code: 1, Stderr: "No journal files were found."}}}
	got, err = Read(failing, root, Day, now)
	if err != nil || len(got) != 1 || got[0].User != "x" || got[0].OK || !got[0].Time.Equal(time.Date(2026, 1, 1, 2, 0, 0, 123456000, time.UTC)) {
		t.Errorf("auth.log: %+v, %v", got, err)
	}

	if _, err := Read(&system.Fake{}, t.TempDir(), Day, now); err == nil {
		t.Error("no journal and no syslog file: want an error")
	}
}
