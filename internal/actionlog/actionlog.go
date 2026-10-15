// Package actionlog owns the global mutation lock and the action log,
// shared by the harden CLI and the TUI.
package actionlog

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	// LockPath is the global mutation lock every mutating action takes.
	LockPath = "/run/vpsctl.lock"
	// LogPath is the action log: one line per mutating action.
	LogPath = "/var/log/vpsctl/actions.log"
)

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

// Append adds one line "<RFC3339 time> <operator> <action>: <result>" to the
// action log at path, creating its directory if needed. It takes only a label
// and a result, so callers never hand it secrets such as private keys.
func Append(path, action, result string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s %s %s: %s\n", time.Now().Format(time.RFC3339), operator(), action, result)
	return err
}

// operator is the real login name behind sudo, else root.
func operator() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	return "root"
}
