package tui

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/system"
)

const cronTail = "journalctl -u cron.service -n 200 --no-pager"

func TestJournalShowsRecentLinesAndScrolls(t *testing.T) {
	h := svcHost(t)
	var b strings.Builder
	for i := range 30 {
		fmt.Fprintf(&b, "cron line %02d\n", i)
	}
	h.fake.Results[cronTail] = system.Result{Stdout: b.String()}

	v := view(openServicesWith(h, "l")) // first row: cron.service
	wantAll(t, v, "Journal: cron.service", "cron line 29", "not following")
	if strings.Contains(v, "cron line 00") {
		t.Errorf("oldest line shown before scrolling up:\n%s", v)
	}

	v = view(openServicesWith(h, "lkkkkkkkkkk"))
	wantAll(t, v, "cron line 00")

	v = view(keys(openServicesWith(h, "l"), "esc"))
	wantAll(t, v, "Services", "nginx.service")
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
	waitFor(t, tm, "filter:")
	if _, err := pw.Write([]byte("late\n")); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("stream still open after leaving the journal: %v", err)
	}
	closeServices(t, tm)
}

func TestJournalUnreadable(t *testing.T) {
	h := svcHost(t)
	h.fake.Results[cronTail] = system.Result{Code: 1, Stderr: "Failed to open journal\n"}
	wantAll(t, view(openServicesWith(h, "l")), "journal unreadable", "Failed to open journal")
}
