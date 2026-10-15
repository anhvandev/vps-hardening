package tui

import (
	"io"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/anhvandev/vpsctl/internal/actionlog"
	"github.com/anhvandev/vpsctl/internal/system"
)

// openTaskHistory opens Task History from the menu.
func openTaskHistory(t *testing.T, tm *teatest.TestModel) {
	t.Helper()
	tm.Type(menuTo("Task History"))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "OPERATOR") // the rows come in the same frame
}

func TestTaskHistoryNewestFirstWithFilter(t *testing.T) {
	h := debianHost(t)
	h.write(actionlog.LogPath,
		"2026-10-01T09:00:00Z alice harden --user bob: ok\n"+
			"2026-10-02T10:30:00Z bob firewall open 8080/tcp: ok\n"+
			"2026-10-03T11:45:00Z alice firewall close 8080/tcp: failed: ufw exited 1\n")
	tm := start(h)
	waitFor(t, tm, "RAM")
	openTaskHistory(t, tm)

	tm.Type("/firewall")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	v := ctrlCView(t, tm)

	wantAll(t, v, "Task History", "TIME", "OPERATOR", "TASK", "RESULT",
		"2026-10-03 11:45:00  alice     firewall close 8080/tcp  failed: ufw exited 1",
		"2026-10-02 10:30:00  bob       firewall open 8080/tcp   ok")
	if strings.Contains(v, "harden --user bob") {
		t.Errorf("filter kept a non-matching line:\n%s", v)
	}
	if strings.Index(v, "close 8080") > strings.Index(v, "open 8080") {
		t.Errorf("not newest first:\n%s", v)
	}
}

func TestTaskHistoryMissing(t *testing.T) {
	tm := start(debianHost(t))
	waitFor(t, tm, "RAM")
	tm.Type(menuTo("Task History"))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "no Tasks yet")
	ctrlCView(t, tm)
}

// A large history loads only its tail: the oldest entry is never read.
func TestTaskHistoryLoadsBoundedTail(t *testing.T) {
	h := debianHost(t)
	var b strings.Builder
	b.WriteString("2020-01-01T00:00:00Z alice ancient action: ok\n")
	for range 20000 {
		b.WriteString("2026-10-01T09:00:00Z alice firewall open 8080/tcp: ok\n")
	}
	b.WriteString("2026-10-14T09:00:00Z alice newest action: ok\n")
	h.write(actionlog.LogPath, b.String())
	tm := start(h)
	waitFor(t, tm, "RAM")
	openTaskHistory(t, tm)
	tm.Type("/ancient")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	wantAll(t, ctrlCView(t, tm), "nothing to show")
}

// Two Tasks run back to back (often in the same second); each entry opens
// its own full output.
func TestTaskHistoryOpensATasksOutput(t *testing.T) {
	h := debianHost(t)
	h.write("/run/.keep", "")
	tm := start(h)
	waitFor(t, tm, "RAM")
	for _, name := range []string{"first", "second"} {
		tm.Send(runTask("Task "+name, "test "+name, name+" done",
			taskStep{"Say " + name, func(_ system.Runner, out io.Writer) error {
				io.WriteString(out, "output of the "+name+" Task\n")
				return nil
			}})())
		waitFor(t, tm, name+" done")
		tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // close the card
		waitFor(t, tm, "q quit")
	}
	openTaskHistory(t, tm)
	tm.Type("j") // the older one
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "output of the first Task")
	v := ctrlCView(t, tm)
	wantAll(t, v, "test first", "[step 1/1] Say first", "Done: first done")
	if strings.Contains(v, "output of the second Task") {
		t.Errorf("opened the wrong output:\n%s", v)
	}
}

// Entries written before Tasks kept their output still list and say so.
func TestTaskHistoryOldEntryHasNoOutput(t *testing.T) {
	h := debianHost(t)
	h.write(actionlog.LogPath, "2026-10-01T09:00:00Z alice harden --user bob: ok\n")
	tm := start(h)
	waitFor(t, tm, "RAM")
	openTaskHistory(t, tm)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "no output recorded")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape}) // back to the list
	waitFor(t, tm, "OPERATOR")                    // the rows come in the same frame
	ctrlCView(t, tm)
}
