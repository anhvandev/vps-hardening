// Package logins reads SSH logins, successful and failed, from the system
// journal on both families (sshd logs as "sshd", or "sshd-session" from
// OpenSSH 9.8 on).
package logins

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/anhvandev/vpsctl/internal/system"
)

// The two windows the Logins screen shows.
const (
	Day  = 24 * time.Hour
	Week = 7 * Day
)

// Login is one SSH connection: OK when it logged in, else a failed attempt.
// Time is when it logged in, or its first failure.
type Login struct {
	Time     time.Time
	User     string
	IP, Port string
	OK       bool
}

var (
	accepted = regexp.MustCompile(`^Accepted \S+ for (\S+) from (\S+) port (\d+)`)
	failed   = []*regexp.Regexp{
		regexp.MustCompile(`^Failed \S+ for (?:invalid user )?(\S*) from (\S+) port (\d+)`),
		regexp.MustCompile(`^Invalid user (\S*) from (\S+) port (\d+)`),
		regexp.MustCompile(`^(?:Connection closed|Disconnected) (?:by|from) (?:invalid|authenticating) user (\S*) (\S+) port (\d+)`),
	}
)

// Read is the SSH connections of the last window before now, newest first.
// A connection logs several lines (Invalid user, Failed password,
// Connection closed …); grouped by process and peer, it counts once.
func Read(r system.Runner, root string, window time.Duration, now time.Time) ([]Login, error) {
	res, err := r.Run("journalctl", "--no-pager", "-q", "-o", "json", fmt.Sprintf("--since=-%dh", int(window.Hours())),
		"SYSLOG_IDENTIFIER=sshd", "+", "SYSLOG_IDENTIFIER=sshd-session")
	if err == nil && res.Code != 0 {
		err = fmt.Errorf("journalctl: %s", strings.TrimSpace(res.Stderr))
	}
	if err != nil {
		return fromFile(root, window, now, err)
	}
	var lines []line
	for _, s := range strings.Split(res.Stdout, "\n") {
		var e struct {
			TS  string `json:"__REALTIME_TIMESTAMP"`
			PID string `json:"_PID"`
			Msg string `json:"MESSAGE"`
		}
		if json.Unmarshal([]byte(s), &e) != nil { // MESSAGE is a byte array when not UTF-8: skipped
			continue
		}
		us, _ := strconv.ParseInt(e.TS, 10, 64)
		lines = append(lines, line{time.UnixMicro(us), e.PID, e.Msg})
	}
	return group(lines), nil
}

// syslogLine is "<RFC 3339 or 'Jan _2 15:04:05'> host sshd[pid]: message".
var syslogLine = regexp.MustCompile(`^(\w{3} +\d+ \d\d:\d\d:\d\d|\S+) \S+ sshd(?:-session)?\[(\d+)\]: (.*)$`)

// fromFile reads the syslog file (Debian auth.log, RHEL secure), for hosts
// whose journal can't be read; jerr is why not.
// ponytail: current file only, not the rotated auth.log.1 (a 7 d window may
// start earlier); read those too if journal-less hosts matter.
func fromFile(root string, window time.Duration, now time.Time, jerr error) ([]Login, error) {
	var b []byte
	var err error
	for _, p := range []string{"/var/log/auth.log", "/var/log/secure"} {
		if b, err = os.ReadFile(filepath.Join(root, p)); err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("no login log: %v; no /var/log/auth.log or /var/log/secure", jerr)
	}
	var lines []line
	for _, s := range strings.Split(string(b), "\n") {
		m := syslogLine.FindStringSubmatch(s)
		if m == nil {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, m[1])
		if err != nil { // the old format has no year: the latest one not in the future
			if t, err = time.ParseInLocation("Jan _2 15:04:05", m[1], now.Location()); err != nil {
				continue
			}
			t = t.AddDate(now.Year(), 0, 0)
			if t.After(now.Add(Day)) {
				t = t.AddDate(-1, 0, 0)
			}
		}
		if t.After(now.Add(-window)) {
			lines = append(lines, line{t, m[2], m[3]})
		}
	}
	return group(lines), nil
}

// line is one sshd log line: when, which sshd process, the message.
type line struct {
	t   time.Time
	pid string
	msg string
}

// group folds lines into one Login per connection (pid, IP, port), newest
// first; an Accepted line makes it a success.
func group(lines []line) []Login {
	byConn := map[string]*Login{}
	var out []*Login
	for _, l := range lines {
		ok, m := true, accepted.FindStringSubmatch(l.msg)
		for _, re := range failed {
			if m != nil {
				break
			}
			ok, m = false, re.FindStringSubmatch(l.msg)
		}
		if m == nil {
			continue
		}
		key := l.pid + " " + m[2] + " " + m[3]
		c := byConn[key]
		if c == nil {
			c = &Login{Time: l.t, User: m[1], IP: m[2], Port: m[3]}
			byConn[key] = c
			out = append(out, c)
		}
		if ok && !c.OK {
			c.Time, c.User, c.OK = l.t, m[1], true
		}
	}
	logins := make([]Login, len(out))
	for i, c := range out {
		logins[i] = *c
	}
	sort.SliceStable(logins, func(i, j int) bool { return logins[i].Time.After(logins[j].Time) })
	return logins
}
