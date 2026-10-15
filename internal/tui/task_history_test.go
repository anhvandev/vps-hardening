package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/anhvandev/vpsctl/internal/actionlog"
)

// openActionLog moves the menu cursor to "Action log" and opens it.
func openActionLog(t *testing.T, tm *teatest.TestModel) {
	t.Helper()
	waitFor(t, tm, "RAM")
	for range menu {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
}

func TestActionLogNewestFirstWithFilter(t *testing.T) {
	h := debianHost(t)
	h.write(actionlog.LogPath,
		"2026-10-01T09:00:00Z alice harden --user bob: ok\n"+
			"2026-10-02T10:30:00Z bob firewall open 8080/tcp: ok\n"+
			"2026-10-03T11:45:00Z alice firewall close 8080/tcp: failed: ufw exited 1\n")
	tm := start(h)
	openActionLog(t, tm)
	waitFor(t, tm, "harden --user bob")

	tm.Type("firewall")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape})
	waitFor(t, tm, "q quit")
	v := quitView(t, tm)

	wantAll(t, v, "filter: firewall", "2026-10-03T11:45:00Z  alice     firewall close 8080/tcp  failed: ufw exited 1",
		"2026-10-02T10:30:00Z  bob       firewall open 8080/tcp  ok")
	if strings.Contains(v, "harden --user bob") {
		t.Errorf("filter kept a non-matching line:\n%s", v)
	}
	if strings.Index(v, "close 8080") > strings.Index(v, "open 8080") {
		t.Errorf("not newest first:\n%s", v)
	}
}

func TestActionLogMissing(t *testing.T) {
	tm := start(debianHost(t))
	openActionLog(t, tm)
	waitFor(t, tm, "no actions yet")
}

// A large log loads only its tail: the oldest line is never read.
func TestActionLogLoadsBoundedTail(t *testing.T) {
	h := debianHost(t)
	var b strings.Builder
	b.WriteString("2020-01-01T00:00:00Z alice ancient action: ok\n")
	for range 20000 {
		b.WriteString("2026-10-01T09:00:00Z alice firewall open 8080/tcp: ok\n")
	}
	b.WriteString("2026-10-14T09:00:00Z alice newest action: ok\n")
	h.write(actionlog.LogPath, b.String())
	tm := start(h)
	openActionLog(t, tm)
	waitFor(t, tm, "newest action")
	tm.Type("ancient")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape})
	waitFor(t, tm, "q quit")
	wantAll(t, quitView(t, tm), "filter: ancient", "no matching actions")
}
