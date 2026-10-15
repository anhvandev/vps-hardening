package tui

// Tasks: a mutation run in the background under the global lock as named
// steps, shown in a panel over the open screen (hideable into the status
// bar), recorded as one Task History line plus a file with its full output.
// The shell owns the Task, so it survives screen changes; quitting waits for
// it and it cannot be cancelled.
//
// A screen starts one by returning runTask(...); when it ends the open screen
// gets a taskDoneMsg (reload on it).

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/anhvandev/vpsctl/internal/actionlog"
	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

// taskStep is one named step of a Task. do runs it: commands go through r,
// which records each command line and its output in the Task's output; out
// takes any other output line. Never run a command whose line or output
// holds a secret through r, and wrap an error whose text may in quiet.
type taskStep struct {
	name string
	do   func(r system.Runner, out io.Writer) error
}

// startTaskMsg asks the shell to run a Task (see runTask).
type startTaskMsg struct {
	name, action, summary string
	steps                 []taskStep
	// logFirst: the last step may end the machine (reboot), so the Task
	// History entry is written, as ok, before it runs; it fails into a
	// second entry.
	logFirst bool
	// summarize, when set, is the Done card's summary, read once the steps
	// ran (Hardening's SUMMARY).
	summarize func() string
}

// runTask is the command a screen returns to run a Task named name, recorded
// in Task History as action, whose Done card shows summary. Steps run in
// order; the first error fails the Task, except a harden.Warning: that step
// is marked warned and the Task goes on. A Task already running, here or in
// another session (global lock), refuses it: nothing runs or is recorded.
func runTask(name, action, summary string, steps ...taskStep) tea.Cmd {
	return func() tea.Msg { return startTaskMsg{name: name, action: action, summary: summary, steps: steps} }
}

// taskDoneMsg goes to the open screen when a Task ends.
type taskDoneMsg struct{}

// Progress of the running Task, sent by its goroutine in order.
type (
	taskStepMsg int    // this step started
	taskWarnMsg int    // this step ended with a harden.Warning
	taskLineMsg string // one output line
	taskEndMsg  struct {
		err     error
		summary string // the summary read at the end, "" to keep the first
	}
	taskGateMsg struct { // waits at the Verify Gate for the answer on reply
		command string
		reply   chan<- bool
	}
	taskTermMsg struct{ lease *termLease } // takes the real terminal
)

// taskGate is harden's ask (ChangeSSH, Run) for a step of the running Task,
// out being the step's out: the Task waits at the Verify Gate, shown in its
// panel with command (see gateCommand) to try from a new terminal, until the
// operator picks Login works (true) or Stop safely (false, the default; also
// ctrl+c).
func taskGate(out io.Writer, command string) func(string) (bool, error) {
	w := out.(*lineWriter)
	return func(string) (bool, error) {
		w.flush()
		reply := make(chan bool, 1)
		w.ch <- taskGateMsg{command, reply}
		return <-reply, nil
	}
}

// taskTerminal is the release for rawKeyMachine in a step of the running
// Task (out is the step's out): the TUI leaves the alternate screen until
// the returned back is called.
func taskTerminal(out io.Writer) func() (back func()) {
	w := out.(*lineWriter)
	return func() func() {
		w.flush()
		l := &termLease{released: make(chan struct{}), done: make(chan struct{})}
		w.ch <- taskTermMsg{l}
		<-l.released
		return func() { close(l.done) }
	}
}

// taskMachine is m with every command run through r, a step's runner, so
// they show in the Task's output. Read anything secret-bearing through m
// instead (ManagedUsers reads shadow).
func taskMachine(m *harden.Machine, r system.Runner) *harden.Machine {
	mm, u, s, p := *m, *m.Manager, *m.SSH, *m.Pkgs
	p.R = r
	u.R, u.Pkgs = r, &p
	s.R, s.Pkgs = r, &p
	mm.Manager, mm.SSH, mm.R, mm.Pkgs = &u, &s, r, &p
	return &mm
}

// task is the shell's view of the current Task.
type task struct {
	name, summary string
	steps         []string
	cur           int   // step running, or the one that failed
	warned        []int // steps that ended with a warning
	lines         []string
	ended         bool
	err           error
	start, end    time.Time
	shown         bool         // the panel is up (else it lives in the status bar)
	full          bool         // the result card shows the output
	gate          *taskGateMsg // the Verify Gate waiting for its answer
	works         bool         // at the gate: "Login works" selected
	events        <-chan tea.Msg
}

func (k *task) wait() tea.Msg { return <-k.events }

// startTask takes the global lock and runs s in the background, showing its panel.
func (t Model) startTask(s startTaskMsg) (tea.Model, tea.Cmd) {
	if t.running() {
		t.refused = fmt.Sprintf("refused: Task %q is running", t.task.name)
		return t, nil
	}
	lk, err := actionlog.Lock(filepath.Join(t.m.Root, actionlog.LockPath))
	if err != nil {
		t.refused = "refused: " + err.Error()
		return t, nil
	}
	ch := make(chan tea.Msg)
	k := &task{name: s.name, summary: s.summary, start: time.Now(), shown: true, events: ch}
	for _, st := range s.steps {
		k.steps = append(k.steps, st.name)
	}
	go s.run(t.m.Root, t.m.R, lk, k.start, ch)
	t.task, t.refused = k, ""
	return t, k.wait
}

// run runs s's steps holding lk, writes its output file and Task History
// line (both dated at), then releases lk and reports the end on ch.
func (s startTaskMsg) run(root string, r system.Runner, lk *os.File, at time.Time, ch chan<- tea.Msg) {
	var file io.Writer = io.Discard // a Task runs even if its output can't be kept
	path := filepath.Join(root, actionlog.OutputPath(at))
	if os.MkdirAll(filepath.Dir(path), 0o700) == nil {
		if f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600); err == nil {
			defer f.Close()
			file = f
		}
	}
	fmt.Fprintf(file, "Task: %s (%s)\n", s.name, s.action)
	out := &lineWriter{file: file, ch: ch}
	var err error
	result := ""
	logged := false
	for i, st := range s.steps {
		ch <- taskStepMsg(i)
		fmt.Fprintf(file, "[step %d/%d] %s\n", i+1, len(s.steps), st.name)
		if s.logFirst && i == len(s.steps)-1 {
			actionlog.AppendAt(filepath.Join(root, actionlog.LogPath), at, s.action, logResult(nil))
			logged = true
		}
		err = st.do(teeRunner{r, out}, out)
		out.flush()
		if errors.As(err, new(harden.Warning)) {
			ch <- taskWarnMsg(i)
			err = nil
		}
		if err != nil {
			result = fmt.Sprintf("step %d/%d %q %s", i+1, len(s.steps), st.name, logResult(err))
			break
		}
	}
	var summary string
	if err == nil {
		if s.summarize != nil {
			summary = s.summarize()
		}
		result = "Done: " + cmp.Or(summary, s.summary)
	}
	fmt.Fprintln(file, result)
	if !logged || err != nil {
		actionlog.AppendAt(filepath.Join(root, actionlog.LogPath), at, s.action, logResult(err)) // failures to log are ignored
	}
	lk.Close()
	ch <- taskEndMsg{err, summary}
}

// lineWriter turns a Task's output into lines: each goes to the output file
// and to the panel.
type lineWriter struct {
	file io.Writer
	ch   chan<- tea.Msg
	buf  []byte
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			return len(p), nil
		}
		w.line(string(w.buf[:i]))
		w.buf = w.buf[i+1:]
	}
}

func (w *lineWriter) line(s string) {
	fmt.Fprintln(w.file, s)
	w.ch <- taskLineMsg(strings.ReplaceAll(s, "\t", "    ")) // tabs would break the panel's border
}

// flush ends a last unterminated line.
func (w *lineWriter) flush() {
	if len(w.buf) > 0 {
		w.line(string(w.buf))
		w.buf = nil
	}
}

// teeRunner records each command line, its output (as it is written when the
// Runner can) and a non-zero exit in out.
type teeRunner struct {
	system.Runner
	out *lineWriter
}

func (t teeRunner) Run(name string, args ...string) (system.Result, error) {
	fmt.Fprintln(t.out, "$", strings.Join(append([]string{name}, args...), " "))
	if l, ok := t.Runner.(system.LiveRunner); ok {
		res, err := l.RunLive(t.out, name, args...)
		t.out.flush() // an unterminated last line
		return res, t.exit(res, err)
	}
	res, err := t.Runner.Run(name, args...)
	for _, s := range []string{res.Stdout, res.Stderr} {
		if s = strings.TrimRight(s, "\n"); s != "" {
			fmt.Fprintln(t.out, s)
		}
	}
	return res, t.exit(res, err)
}

// exit records a command's failure to run or non-zero exit; it returns err.
func (t teeRunner) exit(res system.Result, err error) error {
	switch {
	case err != nil:
		fmt.Fprintln(t.out, err)
	case res.Code != 0:
		fmt.Fprintf(t.out, "exit %d\n", res.Code)
	}
	return err
}

// running reports whether a Task is running.
func (t Model) running() bool { return t.task != nil && !t.task.ended }

// taskUpdate applies the running Task's progress.
func (t Model) taskUpdate(msg tea.Msg) (tea.Model, tea.Cmd) {
	k := t.task
	switch msg := msg.(type) {
	case taskStepMsg:
		k.cur = int(msg)
	case taskWarnMsg:
		k.warned = append(k.warned, int(msg))
	case taskLineMsg:
		k.lines = append(k.lines, string(msg))
	case taskGateMsg:
		k.gate, k.works, k.shown = &msg, false, true
	case taskTermMsg:
		return t, tea.Batch(tea.Exec(msg.lease, nil), k.wait)
	case taskEndMsg:
		k.ended, k.err, k.end = true, msg.err, time.Now()
		k.summary = cmp.Or(msg.summary, k.summary)
		t.busyNote = false
		t.readHardening()
		var cmd tea.Cmd
		t.screen, cmd = t.screen.Update(taskDoneMsg{})
		return t, cmd
	}
	return t, k.wait
}

// panelKey: at the Verify Gate ←/→ choose, enter answers and ctrl+c stops
// safely; while running enter/esc hide the panel; once ended they close
// the result card, and o shows or hides the output.
func (t Model) panelKey(key string) (tea.Model, tea.Cmd) {
	switch {
	case t.task.gate != nil:
		switch key {
		case "left", "right", "tab", "h", "l":
			t.task.works = !t.task.works
		case "ctrl+c":
			t = t.panelButton("Stop safely")
		case "enter":
			t = t.panelButton(map[bool]string{false: "Stop safely", true: "Login works"}[t.task.works])
		}
	case key == "enter" || key == "esc":
		t = t.panelButton(map[bool]string{false: "Hide", true: "Close"}[t.task.ended])
	case key == "o" && t.task.ended:
		t = t.panelButton("View full output")
	}
	return t, nil
}

func (t Model) panelButton(label string) Model {
	if t.task.gate != nil { // only the gate's answers until it has one
		if label == "Login works" || label == "Stop safely" {
			t.task.gate.reply <- label == "Login works"
			t.task.gate = nil
		}
		return t
	}
	switch label {
	case "Hide":
		t.task.shown = false
	case "Close":
		t.task = nil
	case "View full output":
		t.task.full = !t.task.full
	}
	return t
}

// panelClick presses the panel button under a click.
func (t Model) panelClick(msg tea.MouseClickMsg) Model {
	lines := strings.Split(t.frame(), "\n")
	if msg.Button != tea.MouseLeft || msg.Y < 0 || msg.Y >= len(lines) {
		return t
	}
	return t.panelButton(buttonAt(ansi.Strip(lines[msg.Y]), msg.X))
}

// buttonAt is the label of the "[ label ]" button covering column x of line.
func buttonAt(line string, x int) string {
	for i := 0; ; {
		j := strings.Index(line[i:], "[ ")
		if j < 0 {
			return ""
		}
		j += i
		k := strings.Index(line[j:], " ]")
		if k < 0 {
			return ""
		}
		k += j + 2
		if x >= ansi.StringWidth(line[:j]) && x < ansi.StringWidth(line[:k]) {
			return line[j+2 : k-2]
		}
		i = k
	}
}

// mmss is d as "MM:SS".
func mmss(d time.Duration) string {
	s := int(max(d, 0).Seconds())
	return fmt.Sprintf("%02d:%02d", s/60, s%60)
}

// spinner is the running mark, one frame per second.
func (t Model) spinner() string {
	frames := []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
	if ascii.Load() {
		frames = []rune(`|/-\`)
	}
	return string(frames[int(max(t.now.Sub(t.task.start), 0).Seconds())%len(frames)])
}

// taskStatus is the status bar's line for a hidden Task.
func (t Model) taskStatus() string {
	k := t.task
	switch {
	case !k.ended:
		return t.spinner() + " " + k.name + " · " + k.steps[k.cur] + " · " + mmss(t.now.Sub(k.start)) + "   (click to open)"
	case errors.Is(k.err, harden.ErrStopped):
		return warnStyle.Render(glyph("⚠")+" "+k.name+": Stopped") + "   (click to open)"
	case k.err != nil:
		return errStyle.Render(glyph("✗")+" "+k.name+": Failed") + "   (click to open)"
	}
	if len(k.warned) > 0 {
		return warnStyle.Render(glyph("⚠")+" "+k.name+": Done with warnings") + "   (click to open)"
	}
	return okStyle.Render(glyph("✓")+" "+k.name+": Done") + "   (click to open)"
}

// panel is the Task panel, w columns wide and at most h lines high.
func (t Model) panel(w, h int) []string {
	k, bd := t.task, lipgloss.RoundedBorder()
	if ascii.Load() {
		bd = lipgloss.ASCIIBorder()
	}
	cw := w - 4 // content columns
	var body []string
	var state string
	output := func(rows int) {
		ls := k.lines[max(len(k.lines)-max(rows, 1), 0):]
		body = append(body, bd.Top+" output "+strings.Repeat(bd.Top, max(cw-8, 0)))
		body = append(body, ls...)
	}
	switch {
	case !k.ended:
		state = mmss(t.now.Sub(k.start)) + " elapsed"
		for i, s := range k.steps {
			mark := glyph("·")
			switch {
			case slices.Contains(k.warned, i):
				mark = warnStyle.Render(glyph("⚠"))
			case i < k.cur:
				mark = okStyle.Render(glyph("✓"))
			case i == k.cur:
				mark = t.spinner()
			}
			body = append(body, mark+" "+s)
		}
		if k.gate != nil {
			gate := []string{bd.Top + " Verify Gate " + strings.Repeat(bd.Top, max(cw-13, 0))}
			gate = append(gate, strings.Split(lipgloss.NewStyle().Width(cw).Render(
				"The change is live. From your computer, in a NEW terminal (keep this session open), log in with:"), "\n")...)
			works, stop := "[ Login works ]", "[ Stop safely ]"
			if k.works {
				works = selectedStyle.Render(works)
			} else {
				stop = selectedStyle.Render(stop)
			}
			gate = append(gate, "  "+k.gate.command, "then check `sudo true` works. Stop safely restores the pre-change state.",
				works+"  "+stop+"  "+dimStyle.Render("←/→ choose · enter confirm"))
			output(h - len(body) - len(gate) - 3)
			body = append(body, gate...)
			break
		}
		output(h - len(body) - 4)
		btn := "[ Hide ]  (keeps running in the status bar)"
		body = append(body, strings.Repeat(" ", max(cw-ansi.StringWidth(btn), 0))+btn)
	default:
		if errors.Is(k.err, harden.ErrStopped) {
			state = warnStyle.Render(glyph("⚠") + " Stopped")
			reason := fmt.Sprintf("step %d/%d %q: %s", k.cur+1, len(k.steps), k.steps[k.cur], k.err)
			body = append(body, strings.Split(lipgloss.NewStyle().Width(cw).Render(reason), "\n")...)
		} else if k.err != nil {
			state = errStyle.Render(glyph("✗") + " Failed")
			reason := fmt.Sprintf("step %d/%d %q: %s", k.cur+1, len(k.steps), k.steps[k.cur], k.err)
			body = append(body, strings.Split(lipgloss.NewStyle().Width(cw).Render(reason), "\n")...)
		} else {
			state = okStyle.Render(glyph("✓") + " Done in " + mmss(k.end.Sub(k.start)))
			if len(k.warned) > 0 {
				state = warnStyle.Render(glyph("⚠") + " Done with warnings in " + mmss(k.end.Sub(k.start)))
			}
			for i, l := range strings.Split(k.summary, "\n") {
				body = append(body, map[bool]string{true: "SUMMARY  ", false: "         "}[i == 0]+l)
			}
			for _, i := range k.warned {
				body = append(body, warnStyle.Render(glyph("⚠")+" "+k.steps[i]+": not applied, see the output"))
			}
		}
		if k.full {
			output(h - len(body) - 4)
		}
		body = append(body, "[ View full output ]  [ Close ]")
	}
	title := ansi.Truncate(bd.TopLeft+bd.Top+" "+titleStyle.Render("Task: "+k.name)+" ", w-ansi.StringWidth(state)-3, "")
	lines := []string{title + strings.Repeat(bd.Top, max(w-ansi.StringWidth(title)-ansi.StringWidth(state)-3, 0)) + " " + state + " " + bd.TopRight}
	for _, l := range body {
		lines = append(lines, bd.Left+" "+fit(l, cw)+" "+bd.Right)
	}
	return append(lines, bd.BottomLeft+strings.Repeat(bd.Bottom, w-2)+bd.BottomRight)
}

// overlay draws box over base from row y, column x.
func overlay(base, box []string, x, y int) []string {
	for len(base) < y+len(box) {
		base = append(base, "")
	}
	for i, l := range box {
		b := base[y+i]
		base[y+i] = fit(b, x) + l + ansi.Cut(b, x+ansi.StringWidth(l), max(ansi.StringWidth(b), x+ansi.StringWidth(l)))
	}
	return base
}
