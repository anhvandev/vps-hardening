package tui

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/actionlog"
	"github.com/anhvandev/vpsctl/internal/harden"
)

// gateMsg is what a runGated job reports: with ask set it waits at the Verify
// Gate for the operator's answer on ask; with term set it wants the real
// terminal (the shell handles that); otherwise it finished with err.
type gateMsg struct {
	ask  chan<- bool
	term *termLease
	err  error
	next <-chan gateMsg
}

// wait is the command that waits for the job's next gateMsg.
func (g gateMsg) wait() tea.Msg { return <-g.next }

// runGated runs job in the background through logMutation (the global lock
// is held for the whole job, across the Verify Gate), logging a "started"
// line first. job's ask (harden.ChangeSSH's, harden.Run's) turns into a
// gateMsg the screen hands to newVerifyGate; job's result is the last gateMsg.
// job's release leaves the alternate screen and blocks until the TUI has; the
// func it returns gives the terminal back (see rawKeyMachine).
// While it runs, the screen must keep focus (ignore esc) to receive them.
func runGated(root, action string, job func(ask func(string) (bool, error), release func() (back func())) error) tea.Cmd {
	return func() tea.Msg {
		ch := make(chan gateMsg)
		go func() {
			err := logMutation(root, action, func() error {
				actionlog.Append(filepath.Join(root, actionlog.LogPath), action, "started")
				return job(func(string) (bool, error) {
					reply := make(chan bool)
					ch <- gateMsg{ask: reply, next: ch}
					return <-reply, nil
				}, func() func() {
					l := &termLease{released: make(chan struct{}), done: make(chan struct{})}
					ch <- gateMsg{term: l, next: ch}
					<-l.released
					return func() { close(l.done) }
				})
			})
			ch <- gateMsg{err: err, next: ch}
		}()
		return <-ch
	}
}

// termLease is a tea.ExecCommand that holds the TUI off the terminal (out of
// the alternate screen) until the job gives it back.
// ponytail: if bubbletea can't release the terminal, Run never runs and the job waits forever.
type termLease struct{ released, done chan struct{} }

func (l *termLease) Run() error {
	close(l.released)
	<-l.done
	return nil
}
func (*termLease) SetStdin(io.Reader)  {}
func (*termLease) SetStdout(io.Writer) {}
func (*termLease) SetStderr(io.Writer) {}

// rawKeyMachine is m with private keys shown raw on the real terminal: when
// the key code (user.Manager's OpenTTY) opens it, the TUI leaves the
// alternate screen; after the key is printed and `saved` typed, closing it
// returns to the TUI. Run key-emitting work (harden.Run, InstallKey) on it
// inside a runGated job, passing the job's release.
func rawKeyMachine(m *harden.Machine, release func() (back func())) *harden.Machine {
	u := *m.Manager
	open := u.OpenTTY
	if open == nil {
		open = func() (io.ReadWriteCloser, error) { return os.OpenFile("/dev/tty", os.O_RDWR, 0) }
	}
	u.OpenTTY = func() (io.ReadWriteCloser, error) {
		back := release()
		tty, err := open()
		if err != nil {
			back()
			return nil, err
		}
		return leasedTTY{tty, back}, nil
	}
	mm := *m
	mm.Manager = &u
	return &mm
}

type leasedTTY struct {
	io.ReadWriteCloser
	back func()
}

func (t leasedTTY) Close() error {
	defer t.back()
	return t.ReadWriteCloser.Close()
}

// verifyGate is the Verify Gate dialog: the exact ssh command to try from a
// new terminal, then "Login works" or "Stop safely" (the default).
type verifyGate struct {
	msg     gateMsg
	command string
	works   bool // "Login works" selected
}

// newVerifyGate shows the gate msg waits at, for user logging in on port of
// the host the operator's own SSH session came in on.
func newVerifyGate(msg gateMsg, root string, port int, user string) verifyGate {
	host := "<this-host>"
	if f := sshConnection(root); len(f) > 2 {
		host = f[2]
	}
	return verifyGate{msg: msg, command: fmt.Sprintf("ssh -p %d %s@%s", port, user, host)}
}

// Update moves the selection; enter answers, returning the command that
// waits for the job's next gateMsg (the dialog is then done).
func (g verifyGate) Update(msg tea.KeyPressMsg) (verifyGate, tea.Cmd) {
	switch msg.String() {
	case "left", "right", "tab", "h", "l":
		g.works = !g.works
	case "ctrl+c": // quitting here means Stop safely
		g.works = false
		fallthrough
	case "enter":
		return g, func() tea.Msg {
			g.msg.ask <- g.works
			return <-g.msg.next
		}
	}
	return g, nil
}

func (g verifyGate) View() string {
	works, stop := "  Login works  ", "  Stop safely  "
	if g.works {
		works = selectedStyle.Render(works)
	} else {
		stop = selectedStyle.Render(stop)
	}
	return titleStyle.Render("Verify Gate") + "\n\nThe change is live. From your computer, in a NEW terminal\n" +
		"(keep this session open), log in with:\n\n  " + g.command + "\n\nthen check `sudo true` works.\n\n" +
		works + "  " + stop + "\n" + dimStyle.Render("←/→ choose · enter confirm · Stop safely restores the pre-change state")
}
