package tui

import (
	"bufio"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/anhvandev/vpsctl/internal/docker"
)

// dockerLogs follows a container's logs over the Docker screen it was opened
// from; leaving it (esc, or another screen from the sidebar) stops docker logs.
type dockerLogs struct {
	back   tea.Model // the Docker screen
	name   string
	follow *journalStream // nil once it ended
	lines  []string
	scroll int    // lines scrolled up from the newest
	status string // why following stopped
	w, h   int
}

// openDockerLogs opens name's logs on top of back, following from the last
// journalTail lines.
func openDockerLogs(back dockerScreen, name string) (tea.Model, tea.Cmd) {
	l := dockerLogs{back: back, name: name, w: back.w, h: back.h}
	rc, err := docker.Logs(back.m.R, name, journalTail)
	if err != nil {
		l.status = "cannot follow: " + err.Error()
		return l, nil
	}
	l.follow = &journalStream{rc, bufio.NewScanner(rc)}
	return l, l.follow.next
}

// close stops docker logs; the shell calls it when another screen opens.
func (l dockerLogs) close() {
	if l.follow != nil {
		l.follow.rc.Close()
	}
}

func (l dockerLogs) rows() int { return max(l.h-4, 3) }

func (l dockerLogs) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		l.w, l.h = msg.Width, msg.Height
	case journalLineMsg:
		if msg.st != l.follow {
			return l, nil
		}
		if msg.err != nil {
			l.close()
			l.follow, l.status = nil, "follow ended: "+msg.err.Error()
			return l, nil
		}
		l.lines = append(l.lines, ansi.Strip(msg.line)) // a container's escapes must not drive the terminal
		l.lines = l.lines[max(len(l.lines)-journalTail, 0):]
		return l, msg.st.next
	case tea.MouseWheelMsg:
		switch msg.Button {
		case tea.MouseWheelUp:
			l.scroll = min(l.scroll+3, max(len(l.lines)-l.rows(), 0))
		case tea.MouseWheelDown:
			l.scroll = max(l.scroll-3, 0)
		}
	case tea.KeyPressMsg:
		switch msg.String() {
		case "esc":
			l.close()
			return l.back, nil
		case "up", "k":
			l.scroll = min(l.scroll+1, max(len(l.lines)-l.rows(), 0))
		case "down", "j":
			l.scroll = max(l.scroll-1, 0)
		}
	default: // the Docker screen's refreshes and Task results
		var cmd tea.Cmd
		l.back, cmd = l.back.Update(msg)
		return l, cmd
	}
	return l, nil
}

func (l dockerLogs) Init() tea.Cmd { return nil }

func (l dockerLogs) typing() bool { return false }

func (l dockerLogs) keys() string { return "↑↓ scroll · esc back" }

func (l dockerLogs) View() tea.View {
	state := "following live"
	if l.follow == nil {
		state = l.status
	}
	end := len(l.lines) - l.scroll
	var lines []string
	for _, s := range l.lines[max(end-l.rows(), 0):end] {
		lines = append(lines, ansi.Truncate(s, max(l.w, 8), "…"))
	}
	return tea.NewView(titleStyle.Render("Logs: "+l.name) + "  " + dimStyle.Render(state) + "\n\n" + strings.Join(lines, "\n"))
}
