package sshd

import (
	"os"
	"regexp"
	"strings"
)

// Setting is one effective sshd value (from the live `sshd -T`). Overrides
// lists the users for whom a Match block yields a different value.
type Setting struct {
	Key, Value string
	Overrides  []Override
}

// Override is the value a Match block gives User.
type Override struct{ User, Value string }

// Settings returns the effective port and auth settings, each compared with
// the per-user probe (`sshd -T -C user=...`) of every user in users.
func (m *Manager) Settings(users []string) ([]Setting, error) {
	out, err := m.Effective()
	if err != nil {
		return nil, err
	}
	kbd := "kbdinteractiveauthentication"
	if len(values(out, kbd)) == 0 { // EL8's OpenSSH predates it
		kbd = "challengeresponseauthentication"
	}
	var settings []Setting
	for _, k := range []string{"port", "passwordauthentication", kbd, "pubkeyauthentication", "permitrootlogin"} {
		settings = append(settings, Setting{Key: k, Value: strings.Join(values(out, k), ", ")})
	}
	for _, u := range users {
		uout, err := m.Effective("-C", "user="+u+",host=localhost,addr=127.0.0.1")
		if err != nil {
			return nil, err
		}
		for i, s := range settings {
			if v := strings.Join(values(uout, s.Key), ", "); v != s.Value {
				settings[i].Overrides = append(settings[i].Overrides, Override{u, v})
			}
		}
	}
	return settings, nil
}

// Session is one logged-in SSH session. Own marks the operator's session
// (the logind session this process runs in, also under sudo).
type Session struct {
	User, From, Since string
	Own               bool
}

// Sessions lists active SSH sessions from logind.
func (m *Manager) Sessions() ([]Session, error) {
	out, err := m.output("loginctl", "list-sessions", "--no-legend")
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			ids = append(ids, f[0])
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	args := append(append([]string{"show-session"}, ids...), "-p", "Id", "-p", "Name", "-p", "Service", "-p", "RemoteHost", "-p", "Timestamp")
	if out, err = m.output("loginctl", args...); err != nil {
		return nil, err
	}
	own := ""
	if b, err := os.ReadFile(m.path("/proc/self/cgroup")); err == nil {
		if s := regexp.MustCompile(`/session-([^/.]+)\.scope`).FindSubmatch(b); s != nil {
			own = string(s[1])
		}
	}
	var sessions []Session
	// One block of key=value lines per session, blank-line separated.
	for _, block := range strings.Split(out, "\n\n") {
		p := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				p[k] = v
			}
		}
		if p["Service"] == "sshd" {
			sessions = append(sessions, Session{User: p["Name"], From: p["RemoteHost"], Since: p["Timestamp"], Own: p["Id"] == own})
		}
	}
	return sessions, nil
}
