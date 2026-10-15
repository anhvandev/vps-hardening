package tui

import (
	"bufio"
	"cmp"
	"io"
	"strings"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/service"
)

const journalTail = 200 // journal lines read and kept; never the whole history

// journalView shows a Service's recent journal over the Services list it was
// opened from, in a viewport (↑↓/jk, pgup/pgdn, wheel); f toggles live
// follow, which keeps the newest line in view unless scrolled up; esc stops
// it and returns to that list.
type journalView struct {
	back   tea.Model // the Services list
	m      *harden.Machine
	unit   string
	loaded bool
	lines  []string
	err    error // journal unreadable
	vp     viewport.Model
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

// openJournal opens unit's journal on top of back, sized w×h, and starts
// reading its tail.
func openJournal(back tea.Model, m *harden.Machine, unit string, w, h int) (tea.Model, tea.Cmd) {
	j := journalView{back: back, m: m, unit: unit, vp: viewport.New()}
	j.size(w, h)
	return j, func() tea.Msg {
		lines, err := service.Journal(m.R, unit, journalTail)
		return journalMsg{lines, err}
	}
}

// size fits the viewport between the title and the buttons.
func (j *journalView) size(w, h int) {
	j.vp.SetWidth(max(w, 20))
	j.vp.SetHeight(max(h-5, 3))
}

// setLines shows lines, staying at the newest if it was there.
func (j *journalView) setLines(lines []string) {
	bottom := j.vp.AtBottom()
	j.lines = lines[max(len(lines)-journalTail, 0):]
	j.vp.SetContentLines(j.lines)
	if bottom {
		j.vp.GotoBottom()
	}
}

func (j journalView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case journalMsg:
		j.err, j.loaded = msg.err, true
		j.setLines(msg.lines)
		j.vp.GotoBottom()
	case journalLineMsg:
		if msg.st != j.follow {
			return j, nil
		}
		if msg.err != nil {
			j.status = "follow ended: " + msg.err.Error()
			return j.stopFollow(), nil
		}
		j.setLines(append(j.lines, msg.line))
		return j, msg.st.next
	case tea.WindowSizeMsg:
		j.size(msg.Width, msg.Height)
		var cmd tea.Cmd
		j.back, cmd = j.back.Update(msg)
		return j, cmd
	case tea.MouseWheelMsg:
		j.vp, _ = j.vp.Update(msg)
	case tea.MouseClickMsg:
		if m := mouse(j.layout(), msg); m != nil {
			return j.Update(m)
		}
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
			j.follow, j.err, j.status = &journalStream{rc, bufio.NewScanner(rc)}, nil, ""
			j.setLines(nil)
			j.vp.GotoBottom()
			return j, j.follow.next
		default:
			j.vp, _ = j.vp.Update(msg)
		}
	default: // e.g. a refresh tick, or a Task ending
		var cmd tea.Cmd
		j.back, cmd = j.back.Update(msg)
		return j, cmd
	}
	return j, nil
}

func (j journalView) Init() tea.Cmd { return nil }

func (j journalView) typing() bool { return false }

func (j journalView) keys() string { return "↑↓ scroll · f follow · esc back" }

func (j journalView) layout() *lipgloss.Compositor {
	state, follow := "not following", "Follow"
	if j.follow != nil {
		state, follow = "following live", "Stop following"
	}
	body := j.vp.View()
	switch {
	case !j.loaded:
		body = "loading…"
	case j.err != nil:
		body = "journal unreadable: " + j.err.Error()
	}
	blocks := []any{titleStyle.Render("Journal: "+j.unit) + "  " + dimStyle.Render(state), body,
		buttonRow(button{"f", follow, ""}, button{"esc", "Back", ""})}
	if j.status != "" {
		blocks = append(blocks, j.status)
	}
	return stack(blocks...)
}

func (j journalView) View() tea.View {
	return tea.NewView(strings.TrimRight(j.layout().Render(), "\n"))
}
