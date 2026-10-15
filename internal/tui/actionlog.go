package tui

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/actionlog"
	"github.com/anhvandev/vpsctl/internal/harden"
)

func init() { screens["Action log"] = newActionLogView }

const (
	// logTail bounds how much of the action log is read: only its last bytes.
	logTail = 64 << 10
	// logRows bounds how many entries are drawn; the filter narrows the rest.
	logRows = 30
)

// actionLogView lists the action log newest first, narrowed by a typed filter.
type actionLogView struct {
	root    string
	lines   []string // newest first; nil while loading
	missing bool
	filter  string
}

type actionLogMsg struct {
	lines   []string
	missing bool
}

func newActionLogView(m *harden.Machine) tea.Model { return actionLogView{root: m.Root} }

func (a actionLogView) Init() tea.Cmd {
	return func() tea.Msg {
		f, err := os.Open(filepath.Join(a.root, actionlog.LogPath))
		if err != nil {
			return actionLogMsg{missing: true}
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return actionLogMsg{missing: true}
		}
		off := max(st.Size()-logTail, 0)
		b, _ := io.ReadAll(io.NewSectionReader(f, off, st.Size()-off))
		s := string(b)
		if off > 0 { // drop the partial first line
			_, s, _ = strings.Cut(s, "\n")
		}
		lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
		slices.Reverse(lines)
		return actionLogMsg{lines: lines, missing: s == ""}
	}
}

func (a actionLogView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case actionLogMsg:
		a.lines, a.missing = msg.lines, msg.missing
	case tea.KeyPressMsg:
		switch msg.String() {
		case "esc":
			return a, Back
		case "backspace":
			if a.filter != "" {
				a.filter = a.filter[:len(a.filter)-1]
			}
		default:
			a.filter += msg.Text
		}
	}
	return a, nil
}

func (a actionLogView) View() tea.View {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Action log") + "\n")
	fmt.Fprintf(&b, "filter: %s\n", a.filter)
	switch {
	case a.missing:
		return tea.NewView(b.String() + "\nno actions yet")
	case a.lines == nil:
		return tea.NewView(b.String() + "\nloading…")
	}
	n := 0
	for _, line := range a.lines {
		if !strings.Contains(strings.ToLower(line), strings.ToLower(a.filter)) {
			continue
		}
		if n++; n > logRows {
			fmt.Fprintf(&b, "\n… more, type to filter")
			break
		}
		// "<time> <operator> <action>: <result>"
		f := strings.SplitN(line, " ", 3)
		if len(f) < 3 {
			b.WriteString("\n" + line)
			continue
		}
		action, result, _ := strings.Cut(f[2], ": ")
		fmt.Fprintf(&b, "\n%s  %-8s  %s  %s", f[0], f[1], action, result)
	}
	if n == 0 {
		b.WriteString("\nno matching actions")
	}
	return tea.NewView(b.String())
}
