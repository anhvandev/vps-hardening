package tui

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/system"
)

const cronTail = "journalctl -u cron.service -n 200 --no-pager"

// cronJournal scripts 60 lines of cron's journal, more than fit.
func cronJournal(h *testHost) {
	var b strings.Builder
	for i := range 60 {
		fmt.Fprintf(&b, "cron line %02d\n", i)
	}
	h.fake.Results[cronTail] = system.Result{Stdout: b.String()}
}

func TestJournalShowsRecentLinesAndScrolls(t *testing.T) {
	h := svcHost(t)
	cronJournal(h)

	v := view(openServicesWith(h, "l")) // first row: cron.service
	wantAll(t, v, "Journal: cron.service", "cron line 59", "not following", "[ Follow ]")
	if strings.Contains(v, "cron line 00") {
		t.Errorf("oldest line shown before scrolling up:\n%s", v)
	}

	v = view(openServicesWith(h, "l"+strings.Repeat("k", 30)))
	wantAll(t, v, "cron line 00")

	v = view(keys(openServicesWith(h, "l"), "esc"))
	wantAll(t, v, "Services", "nginx.service")
}

// The wheel scrolls the journal, in the shell.
func TestJournalWheelScrolls(t *testing.T) {
	h := svcHost(t)
	cronJournal(h)
	tm := openServices(t, h)
	tm.Type("l")
	waitFor(t, tm, "cron line 59")
	for range 10 {
		tm.Send(tea.MouseWheelMsg{X: 60, Y: 10, Button: tea.MouseWheelUp})
	}
	wantAll(t, ctrlCView(t, tm), "cron line 00")
}

// Follow shows lines as the stream writes them, keys still work while it
// waits, and leaving the journal closes the stream.
func TestJournalFollowStreamsUntilLeft(t *testing.T) {
	h := svcHost(t)
	h.fake.Results[cronTail] = system.Result{Stdout: "cron old line\n"}
	pr, pw := io.Pipe()
	h.fake.Streams = map[string]io.ReadCloser{"journalctl -u cron.service -n 200 -f --no-pager": pr}
	tm := openServices(t, h)
	tm.Type("l")
	waitFor(t, tm, "cron old line")
	tm.Type("f")
	waitFor(t, tm, "following live")
	go pw.Write([]byte("cron old line\ncron new line\n"))
	waitFor(t, tm, "cron new line")

	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape}) // stream idle, TUI not blocked on it
	waitFor(t, tm, "filter: [")
	if _, err := pw.Write([]byte("late\n")); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("stream still open after leaving the journal: %v", err)
	}
	ctrlCView(t, tm)
}

// pipeClosed reports whether w's reader was closed (the child stopped):
// a write fails at once, else it is read or blocks.
func pipeClosed(w io.Writer) bool {
	done := make(chan error, 1)
	go func() { _, err := io.WriteString(w, "late\n"); done <- err }()
	select {
	case err := <-done:
		return errors.Is(err, io.ErrClosedPipe)
	case <-time.After(time.Second):
		return false
	}
}

// Leaving a followed journal through the sidebar, or quitting, stops
// journalctl too.
func TestJournalFollowStopsOnSidebarAndQuit(t *testing.T) {
	for _, leave := range []string{"sidebar", "quit"} {
		t.Run(leave, func(t *testing.T) {
			h := svcHost(t)
			h.fake.Results[cronTail] = system.Result{Stdout: "cron old line\n"}
			pr, pw := io.Pipe()
			h.fake.Streams = map[string]io.ReadCloser{"journalctl -u cron.service -n 200 -f --no-pager": pr}
			tm := openServices(t, h)
			tm.Type("l")
			waitFor(t, tm, "cron old line")
			tm.Type("f")
			waitFor(t, tm, "following live")
			if leave == "sidebar" {
				tm.Send(tea.KeyPressMsg{Code: tea.KeyTab})
				tm.Type(strings.Repeat("j", slices.Index(items(), "Overview")-slices.Index(items(), "Services")))
				tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
				waitFor(t, tm, "Uptime")
				if !pipeClosed(pw) {
					t.Error("journalctl still running after leaving through the sidebar")
				}
			}
			ctrlCView(t, tm)
			if !pipeClosed(pw) {
				t.Error("journalctl still running")
			}
		})
	}
}

func TestJournalUnreadable(t *testing.T) {
	h := svcHost(t)
	h.fake.Results[cronTail] = system.Result{Code: 1, Stderr: "Failed to open journal\n"}
	wantAll(t, view(openServicesWith(h, "l")), "journal unreadable", "Failed to open journal")
}
