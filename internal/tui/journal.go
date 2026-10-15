package tui

import (
	"bufio"
	"cmp"
	"io"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/service"
)

const (
	journalTail = 200 // journal lines read and kept; never the whole history
	journalRows = 20  // journal lines drawn; ↑/↓ scroll the rest
)

// journalView shows a Service's recent journal over the Services list it was
// opened from; f toggles live follow, esc stops it and returns to that list.
type journalView struct {
	back   tea.Model // the Services list
	m      *harden.Machine
	unit   string
	loaded bool
	lines  []string
	err    error // journal unreadable
	scroll int   // lines scrolled up from the newest
	follow *journalStream
	status string // why following stopped, "" if it did not
}

// journalMsg is one read of the journal tail.
type journalMsg struct {
	lines []string
	err   error
}

// journalStream is a running follow; its lines are read one per command so
// the TUI never waits on journalctl.
type journalStream struct {
	rc io.ReadCloser
	sc *bufio.Scanner
}

// journalLineMsg is the next line of st, or err once st has ended.
type journalLineMsg struct {
	st   *journalStream
	line string
	err  error
}

func (st *journalStream) next() tea.Msg {
	if st.sc.Scan() {
		return journalLineMsg{st: st, line: st.sc.Text()}
	}
	return journalLineMsg{st: st, err: cmp.Or(st.sc.Err(), io.EOF)}
}

// stopFollow closes the stream (stopping journalctl); its pending read ends
// with an error that Update ignores, as st is no longer current.
func (j journalView) stopFollow() journalView {
	if j.follow != nil {
		j.follow.rc.Close()
		j.follow = nil
	}
	return j
}

// openJournal opens unit's journal on top of back and starts reading its tail.
func openJournal(back tea.Model, m *harden.Machine, unit string) (tea.Model, tea.Cmd) {
	return journalView{back: back, m: m, unit: unit}, func() tea.Msg {
		lines, err := service.Journal(m.R, unit, journalTail)
		return journalMsg{lines, err}
	}
}

func (j journalView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case journalMsg:
		j.lines, j.err, j.loaded = msg.lines, msg.err, true
	case journalLineMsg:
		if msg.st != j.follow {
			return j, nil
		}
		if msg.err != nil {
			j.status = "follow ended: " + msg.err.Error()
			return j.stopFollow(), nil
		}
		j.lines = append(j.lines, msg.line)
		j.lines = j.lines[max(len(j.lines)-journalTail, 0):]
		return j, msg.st.next
	case tea.KeyPressMsg:
		switch msg.String() {
		case "esc":
			return j.stopFollow().back, nil
		case "f":
			if j.follow != nil || !j.loaded {
				return j.stopFollow(), nil
			}
			// The stream replays the tail itself, so nothing logged since it was read is missed.
			rc, err := service.Follow(j.m.R, j.unit, journalTail)
			if err != nil {
				j.status = "cannot follow: " + err.Error()
				return j, nil
			}
			j.follow, j.lines, j.err, j.scroll, j.status = &journalStream{rc, bufio.NewScanner(rc)}, nil, nil, 0, ""
			return j, j.follow.next
		case "up", "k":
			j.scroll = min(j.scroll+1, max(len(j.lines)-journalRows, 0))
		case "down", "j":
			j.scroll = max(j.scroll-1, 0)
		}
	default: // e.g. the outcome of a lifecycle action still running
		var cmd tea.Cmd
		j.back, cmd = j.back.Update(msg)
		return j, cmd
	}
	return j, nil
}

func (j journalView) Init() tea.Cmd { return nil }

func (j journalView) View() tea.View {
	var b strings.Builder
	state := "not following"
	if j.follow != nil {
		state = "following live"
	}
	b.WriteString(titleStyle.Render("Journal: "+j.unit) + "  " + dimStyle.Render(state) + "\n\n")
	switch {
	case !j.loaded:
		b.WriteString("loading…")
	case j.err != nil:
		b.WriteString("journal unreadable: " + j.err.Error())
	default:
		end := len(j.lines) - j.scroll
		b.WriteString(strings.Join(j.lines[max(end-journalRows, 0):end], "\n"))
	}
	b.WriteString("\n\n" + dimStyle.Render("f follow · ↑/↓ scroll · esc back"))
	if j.status != "" {
		b.WriteString("\n\n" + j.status)
	}
	return tea.NewView(b.String())
}
