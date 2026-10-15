package tui

import (
	"slices"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/anhvandev/vpsctl/internal/system"
)

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
			tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape})
			waitFor(t, tm, "q quit")
			quitView(t, tm)
		})
	}
}
