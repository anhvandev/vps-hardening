// Package actionlog owns the global mutation lock and the action log,
// shared by the harden CLI and the TUI.
package actionlog

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

// LockPath is the global mutation lock every mutating action takes.
const LockPath = "/run/vpsctl.lock"

// Lock takes the global mutation lock at path; the kernel drops it when the
// process exits. A busy lock returns "locked by <user> (pid N)".
func Lock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		holder, _ := io.ReadAll(f)
		f.Close()
		return nil, fmt.Errorf("locked by %s", strings.TrimSpace(string(holder)))
	}
	f.Truncate(0)
	fmt.Fprintf(f, "%s (pid %d)\n", operator(), os.Getpid())
	return f, nil
}

// operator is the real login name behind sudo, else root.
func operator() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	return "root"
}
