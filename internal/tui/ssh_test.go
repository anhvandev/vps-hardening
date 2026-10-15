package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/system"
)

// A Match block re-enabling password auth for a Managed User is flagged; the
// operator's own session is marked.
func TestSSHScreenFlagsMatchOverrideAndOwnSession(t *testing.T) {
	h := debianHost(t)
	global := "port 22\npasswordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\npermitrootlogin no\n"
	for k, v := range map[string]string{
		"getent passwd": "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/bash\n",
		"getent group":  "sudo:x:27:alice\n",
		"getent shadow": "alice:!:19000:0:99999:7:::\nbob:!:19000:0:99999:7:::\n",
		"sshd -T":       global,
		"sshd -T -C user=alice,host=localhost,addr=127.0.0.1": global,
		"sshd -T -C user=bob,host=localhost,addr=127.0.0.1":   strings.Replace(global, "passwordauthentication no", "passwordauthentication yes", 1),
		"loginctl list-sessions --no-legend":                  "5 1000 alice pts/0\n7 1001 bob pts/1\n",
		"loginctl show-session 5 7 -p Id -p Name -p Service -p RemoteHost -p Timestamp": "Id=5\nName=alice\nService=sshd\nRemoteHost=203.0.113.5\nTimestamp=Thu 2026-10-15 09:12:03 UTC\n\n" +
			"Id=7\nName=bob\nService=sshd\nRemoteHost=198.51.100.7\nTimestamp=Thu 2026-10-15 10:00:00 UTC\n",
	} {
		h.fake.Results[k] = system.Result{Stdout: v}
	}
	h.write("/etc/ssh/ssh_host_ed25519_key", "k")
	h.write("/proc/self/cgroup", "0::/user.slice/user-1000.slice/session-5.scope\n")
	tm := start(h)
	waitFor(t, tm, "RAM")
	tm.Type("jjj") // Overview → Hardening → Firewall → SSH
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "198.51.100.7")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape})
	waitFor(t, tm, "q quit")
	v := quitView(t, tm)
	wantAll(t, v, "passwordauthentication", "Match: bob=yes", "permitrootlogin",
		"alice", "203.0.113.5", "Thu 2026-10-15 09:12:03 UTC", "(you)", "bob")
	if strings.Count(v, "(you)") != 1 {
		t.Errorf("want exactly one own session:\n%s", v)
	}
}
