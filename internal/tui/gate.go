package tui

import (
	"fmt"
	"path/filepath"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/actionlog"
)

// gateMsg is what a runGated job reports: with ask set it waits at the Verify
// Gate for the operator's answer on ask; otherwise it finished with err.
type gateMsg struct {
	ask  chan<- bool
	err  error
	next <-chan gateMsg
}

// runGated runs job in the background through logMutation (the global lock
// is held for the whole job, across the Verify Gate), logging a "started"
// line first. job's ask (harden.ChangeSSH's, harden.Run's) turns into a
// gateMsg the screen hands to newVerifyGate; job's result is the last gateMsg.
// While it runs, the screen must keep focus (ignore esc) to receive them.
func runGated(root, action string, job func(ask func(string) (bool, error)) error) tea.Cmd {
	return func() tea.Msg {
		ch := make(chan gateMsg)
		go func() {
			err := logMutation(root, action, func() error {
				actionlog.Append(filepath.Join(root, actionlog.LogPath), action, "started")
				return job(func(string) (bool, error) {
					reply := make(chan bool)
					ch <- gateMsg{ask: reply, next: ch}
					return <-reply, nil
				})
			})
			ch <- gateMsg{err: err, next: ch}
		}()
		return <-ch
	}
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
