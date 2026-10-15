package tui

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/anhvandev/vpsctl/internal/actionlog"
	"github.com/anhvandev/vpsctl/internal/system"
)

// f2bHost is debianHost with fail2ban running two jails (two bans in sshd)
// and /run present for the global lock.
func f2bHost(t *testing.T) *testHost {
	h := debianHost(t)
	h.fake.Results["fail2ban-client status"] = system.Result{Stdout: "Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, recidive\n"}
	h.fake.Results["fail2ban-client status sshd"] = system.Result{Stdout: "Status for the jail: sshd\n|- Filter\n|  `- Total failed:\t9\n" +
		"`- Actions\n   |- Currently banned:\t2\n   |- Total banned:\t2\n   `- Banned IP list:\t198.51.100.7 2001:db8::9\n"}
	h.fake.Results["fail2ban-client status recidive"] = system.Result{Stdout: "Status for the jail: recidive\n" +
		"`- Actions\n   |- Currently banned:\t0\n   `- Banned IP list:\t\n"}
	h.fake.Results["fail2ban-client set sshd unbanip 2001:db8::9"] = system.Result{Stdout: "1\n"}
	if err := os.MkdirAll(filepath.Join(h.root, "/run"), 0o755); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *testHost) actionLog() string {
	b, _ := os.ReadFile(filepath.Join(h.root, actionlog.LogPath))
	return string(b)
}

func TestFail2banUnbanSelectedIP(t *testing.T) {
	h := f2bHost(t)
	tm := openFail2ban(h)
	waitFor(t, tm, "2001:db8::9")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Type("u")
	waitFor(t, tm, "unbanned 2001:db8::9")
	v := closeF2b(t, tm)
	wantAll(t, v, "sshd", "recidive", "198.51.100.7")
	if !slices.Contains(h.fake.Calls, "fail2ban-client set sshd unbanip 2001:db8::9") {
		t.Errorf("no unban call in %q", h.fake.Calls)
	}
	if log := h.actionLog(); !strings.Contains(log, "fail2ban unban 2001:db8::9 sshd: ok") {
		t.Errorf("action log = %q", log)
	}
}

func TestFail2banUnbanWhileLockedShowsHolder(t *testing.T) {
	h := f2bHost(t)
	lk, err := actionlog.Lock(filepath.Join(h.root, actionlog.LockPath))
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Close()
	tm := openFail2ban(h)
	waitFor(t, tm, "198.51.100.7")
	tm.Type("u")
	waitFor(t, tm, "locked by")
	closeF2b(t, tm)
	for _, c := range h.fake.Calls {
		if strings.Contains(c, "unbanip") {
			t.Errorf("unbanned while locked: %q", c)
		}
	}
}

// openFail2ban starts the TUI on h and opens the fail2ban screen.
func openFail2ban(h *testHost) *teatest.TestModel {
	tm := start(h)
	waitFor(h.t, tm, "RAM")
	for range slices.Index(menu, "fail2ban") {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	return tm
}

// closeF2b leaves the screen with esc, quits and returns the last frame.
func closeF2b(t *testing.T, tm *teatest.TestModel) string {
	t.Helper()
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape})
	waitFor(t, tm, "q quit")
	return quitView(t, tm)
}

func TestFail2banMissingOrStoppedIsAState(t *testing.T) {
	for _, tc := range []struct {
		name string
		res  *system.Result
		want string
	}{
		{"not installed", nil, "fail2ban is not installed"},
		{"inactive", &system.Result{Code: 255, Stderr: "Failed to access socket path"}, "fail2ban is not running"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := debianHost(t)
			delete(h.fake.Results, "fail2ban-client status")
			if tc.res != nil {
				h.fake.Results["fail2ban-client status"] = *tc.res
			}
			tm := openFail2ban(h)
			waitFor(t, tm, tc.want)
			closeF2b(t, tm)
		})
	}
}
