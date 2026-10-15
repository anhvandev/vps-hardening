package sshd

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/anhvandev/vpsctl/internal/system"
)

const globalT = "port 22\npasswordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\npermitrootlogin no\nusepam yes\n"

// scripted is a Manager over a Fake with the given results and files under a
// temp root; host keys exist so no ssh-keygen runs.
func scripted(t *testing.T, results map[string]system.Result, files map[string]string) *Manager {
	root := t.TempDir()
	files["/etc/ssh/ssh_host_ed25519_key"] = "k"
	for p, s := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &Manager{R: &system.Fake{Results: results}, Root: root}
}

func probe(user string) string { return "sshd -T -C user=" + user + ",host=localhost,addr=127.0.0.1" }

func TestSettingsFlagMatchBlockReenablingPasswordAuth(t *testing.T) {
	m := scripted(t, map[string]system.Result{
		"sshd -T":      {Stdout: globalT},
		probe("alice"): {Stdout: globalT},
		// Match User bob → PasswordAuthentication yes
		probe("bob"): {Stdout: "port 22\npasswordauthentication yes\nkbdinteractiveauthentication no\npubkeyauthentication yes\npermitrootlogin no\n"},
	}, map[string]string{})
	got, err := m.Settings([]string{"alice", "bob"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Setting{
		{Key: "port", Value: "22"},
		{Key: "passwordauthentication", Value: "no", Overrides: []Override{{User: "bob", Value: "yes"}}},
		{Key: "kbdinteractiveauthentication", Value: "no"},
		{Key: "pubkeyauthentication", Value: "yes"},
		{Key: "permitrootlogin", Value: "no"},
	}
	if !slices.EqualFunc(got, want, func(a, b Setting) bool {
		return a.Key == b.Key && a.Value == b.Value && slices.Equal(a.Overrides, b.Overrides)
	}) {
		t.Errorf("Settings =\n%+v\nwant\n%+v", got, want)
	}
}

// EL8's OpenSSH reports challengeresponseauthentication instead.
func TestSettingsOnOldOpenSSH(t *testing.T) {
	out := "port 2222\npasswordauthentication yes\nchallengeresponseauthentication yes\npubkeyauthentication yes\npermitrootlogin yes\n"
	m := scripted(t, map[string]system.Result{"sshd -T": {Stdout: out}}, map[string]string{})
	got, err := m.Settings(nil)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, s := range got {
		keys = append(keys, s.Key+"="+s.Value)
	}
	want := []string{"port=2222", "passwordauthentication=yes", "challengeresponseauthentication=yes", "pubkeyauthentication=yes", "permitrootlogin=yes"}
	if !slices.Equal(keys, want) {
		t.Errorf("got %v, want %v", keys, want)
	}
}

func TestSettingsFailWhenSshdTFails(t *testing.T) {
	m := scripted(t, map[string]system.Result{"sshd -T": {Code: 255, Stderr: "bad config line 3"}}, map[string]string{})
	if _, err := m.Settings(nil); err == nil {
		t.Fatal("want error")
	}
}

func TestSessionsListSSHLoginsAndMarkOwn(t *testing.T) {
	m := scripted(t, map[string]system.Result{
		"loginctl list-sessions --no-legend": {Stdout: "     3    0 root  seat0 tty1\n     5 1000 alice       pts/0\n     7 1001 bob         pts/1\n"},
		"loginctl show-session 3 5 7 -p Id -p Name -p Service -p RemoteHost -p Timestamp": {Stdout: "Id=3\nName=root\nTimestamp=Wed 2026-10-14 08:00:00 UTC\nService=login\nRemoteHost=\n\n" +
			"Id=5\nName=alice\nTimestamp=Thu 2026-10-15 09:12:03 UTC\nService=sshd\nRemoteHost=203.0.113.5\n\n" +
			"Id=7\nName=bob\nTimestamp=Thu 2026-10-15 10:00:00 UTC\nService=sshd\nRemoteHost=198.51.100.7\n"},
	}, map[string]string{"/proc/self/cgroup": "0::/user.slice/user-1000.slice/session-5.scope\n"})
	got, err := m.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	want := []Session{
		{User: "alice", From: "203.0.113.5", Since: "Thu 2026-10-15 09:12:03 UTC", Own: true},
		{User: "bob", From: "198.51.100.7", Since: "Thu 2026-10-15 10:00:00 UTC"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("Sessions =\n%+v\nwant\n%+v", got, want)
	}
}

func TestSessionsNoneLoggedIn(t *testing.T) {
	m := scripted(t, map[string]system.Result{"loginctl list-sessions --no-legend": {}}, map[string]string{})
	got, err := m.Sessions()
	if err != nil || len(got) != 0 {
		t.Fatalf("Sessions = %v, %v; want none", got, err)
	}
}
