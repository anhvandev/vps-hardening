// Package actionlog owns the global mutation lock and the action log,
// shared by the harden CLI and the TUI.
package actionlog

import (
	"cmp"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/anhvandev/vpsctl/internal/system"
)

const (
	// LockPath is the global mutation lock every mutating action takes.
	LockPath = "/run/vpsctl.lock"
	// LogPath is the action log (Task History): one line per mutating action.
	LogPath = "/var/log/vpsctl/actions.log"
	// TaskDir holds each Task's full output, one file per Task (OutputPath).
	TaskDir = "/var/log/vpsctl/tasks"
)

// OutputPath is the output file of the Task whose Task History line carries
// time at (second resolution, local time).
// ponytail: two Tasks started in the same second share one file; add a suffix if that ever matters.
func OutputPath(at time.Time) string {
	return filepath.Join(TaskDir, at.Format("20060102-150405")+".log")
}

// Lock takes the global mutation lock at path; the kernel drops it when the
// process exits. A busy lock returns "locked by <user> (pid N)".
func Lock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	// A few short retries ride out Holder's instant probe; a real holder keeps it far longer.
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	for i := 0; err != nil && i < 5; i++ {
		time.Sleep(10 * time.Millisecond)
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	}
	if err != nil {
		holder, _ := io.ReadAll(f)
		f.Close()
		return nil, fmt.Errorf("locked by %s", strings.TrimSpace(string(holder)))
	}
	f.Truncate(0)
	fmt.Fprintf(f, "%s (pid %d)\n", operator(), os.Getpid())
	return f, nil
}

// Holder is who holds the global mutation lock at path ("<user> (pid N)"),
// "" when it is free. It never creates the lock file.
// The probe holds a shared lock for an instant; Lock retries briefly to ride it out.
func Holder(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close() // drops the probe
	if syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB) == nil {
		return ""
	}
	holder, _ := io.ReadAll(f)
	return strings.TrimSpace(string(holder))
}

// Append adds one line "<RFC3339 time> <operator> <action>: <result>" to the
// action log at path, creating its directory if needed. It takes only a label
// and a result, so callers never hand it secrets such as private keys.
func Append(path, action, result string) error {
	return AppendAt(path, time.Now(), action, result)
}

// AppendAt is Append with the line's time given (a Task's start, which also
// names its output file).
func AppendAt(path string, at time.Time, action, result string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s %s %s: %s\n", at.Format(time.RFC3339), operator(), action, result)
	return err
}

// operator is the real login name behind sudo, else root.
func operator() string { return cmp.Or(system.SessionUser(), "root") }
