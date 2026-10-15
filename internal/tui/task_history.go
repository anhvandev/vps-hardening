package tui

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/anhvandev/vpsctl/internal/actionlog"
	"github.com/anhvandev/vpsctl/internal/harden"
)

func init() { screens["Task History"] = newTaskHistory }

// historyTail bounds how much of Task History is read: only its last bytes.
const historyTail = 64 << 10

// taskHistory lists Task History newest first (time, operator, Task,
// result); enter opens the selected Task's full output in a viewport.
// Entries recorded before Tasks kept their output say so.
type taskHistory struct {
	root    string
	loaded  bool
	lines   []string // newest first
	table   table
	reading bool // an output is shown
	head    string
	out     viewport.Model
	w, h    int
}

type historyMsg []string

// outputMsg is one Task's output file, read; text is "" when there is none.
type outputMsg struct{ head, text string }

func newTaskHistory(m *harden.Machine) tea.Model {
	return taskHistory{root: m.Root, table: newTable("TIME", "OPERATOR", "TASK", "RESULT")}
}

func (s taskHistory) Init() tea.Cmd {
	return func() tea.Msg {
		f, err := os.Open(filepath.Join(s.root, actionlog.LogPath))
		if err != nil {
			return historyMsg(nil)
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return historyMsg(nil)
		}
		off := max(st.Size()-historyTail, 0)
		b, _ := io.ReadAll(io.NewSectionReader(f, off, st.Size()-off))
		text := string(b)
		if off > 0 { // drop the partial first line
			_, text, _ = strings.Cut(text, "\n")
		}
		if text = strings.TrimRight(text, "\n"); text == "" {
			return historyMsg(nil)
		}
		lines := strings.Split(text, "\n")
		slices.Reverse(lines)
		return historyMsg(lines)
	}
}

// entry splits a "<time> <operator> <action>: <result>" line; at is zero
// when the time does not parse.
func entry(line string) (at time.Time, row []string) {
	f := strings.SplitN(line, " ", 3)
	if len(f) < 3 {
		return at, []string{"", "", line, ""}
	}
	action, result, _ := strings.Cut(f[2], ": ")
	at, err := time.Parse(time.RFC3339, f[0])
	if err != nil {
		return at, []string{f[0], f[1], action, result}
	}
	return at, []string{at.Format("2006-01-02 15:04:05"), f[1], action, result}
}

// output reads the output file of the Task on line.
func (s taskHistory) output(line string) tea.Cmd {
	return func() tea.Msg {
		at, row := entry(line)
		msg := outputMsg{head: row[2] + " · " + row[0] + " · " + row[3]}
		if !at.IsZero() {
			b, _ := os.ReadFile(filepath.Join(s.root, actionlog.OutputPath(at)))
			msg.text = strings.ReplaceAll(string(b), "\t", "    ")
		}
		return msg
	}
}

func (s taskHistory) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		s.w, s.h = msg.Width, msg.Height
		s.table.height = max(s.h-6, 3) // room for the title, filter, box and buttons
		s.table.setRows(s.table.rows)
		s.out.SetWidth(s.w)
		s.out.SetHeight(max(s.h-2, 1))
		return s, nil
	case historyMsg:
		s.lines, s.loaded = msg, true
		var rows [][]string
		for _, l := range s.lines {
			_, row := entry(l)
			rows = append(rows, row)
		}
		s.table.setRows(rows)
		return s, nil
	case taskDoneMsg:
		return s, s.Init()
	case outputMsg:
		s.reading, s.head = true, msg.head
		s.out = viewport.New(viewport.WithWidth(s.w), viewport.WithHeight(max(s.h-2, 1)))
		s.out.SetContent(msg.text)
		if msg.text == "" {
			s.out.SetContent(dimStyle.Render("no output recorded (this entry predates Task output)"))
		}
		return s, nil
	}
	if s.reading {
		if k, ok := msg.(tea.KeyPressMsg); ok && k.String() == "esc" {
			s.reading = false
			return s, nil
		}
		var cmd tea.Cmd
		s.out, cmd = s.out.Update(msg)
		return s, cmd
	}
	if c, ok := msg.(tea.MouseClickMsg); ok {
		if m := mouse(s.layout(), c); m != nil {
			return s.Update(m)
		}
		return s, nil
	}
	if t, ok := s.table.update(msg); ok {
		s.table = t
		return s, nil
	}
	k, ok := msg.(tea.KeyPressMsg)
	if !ok || disabled(s.buttons(), k.String()) {
		return s, nil
	}
	switch k.String() {
	case "esc":
		return s, Back
	case "enter":
		return s, s.output(s.lines[s.table.selected()])
	}
	return s, nil
}

func (s taskHistory) typing() bool { return !s.reading && s.table.typing() }

func (s taskHistory) keys() string {
	switch {
	case s.reading:
		return "↑↓ scroll · esc back"
	case s.table.typing():
		return s.table.keys()
	}
	return s.table.keys() + " · " + keyHelp(s.buttons()) + " · esc back"
}

func (s taskHistory) buttons() []button {
	b := button{"enter", "View output", ""}
	if s.table.selected() < 0 {
		b.why = "no Task selected"
	}
	return []button{b}
}

// layout is the screen: title, Task table and buttons, or one Task's output.
func (s taskHistory) layout() *lipgloss.Compositor {
	title := titleStyle.Render("Task History")
	switch {
	case s.reading:
		return stack(title+"  "+s.head, s.out.View())
	case !s.loaded:
		return stack(title, "", "loading…")
	case len(s.lines) == 0:
		return stack(title, "", "no Tasks yet")
	}
	return stack(title, s.table.layer(s.w), buttonRow(s.buttons()...))
}

func (s taskHistory) View() tea.View { return tea.NewView(s.layout().Render()) }
