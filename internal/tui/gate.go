package tui

import (
	"fmt"
	"io"
	"os"

	"github.com/anhvandev/vpsctl/internal/harden"
)

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
// returns to the TUI. Run key-emitting work (Hardening, GenerateKey) on it
// in a Task step, release being taskTerminal(out).
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

// gateCommand is the login to try at the Verify Gate: user on port of the
// host the operator's own SSH session came in on.
func gateCommand(root string, port int, user string) string {
	host := "<this-host>"
	if f := sshConnection(root); len(f) > 2 {
		host = f[2]
	}
	return fmt.Sprintf("ssh -p %d %s@%s", port, user, host)
}
