// Package system is vpsctl's only door to the host: every command goes through
// a Runner so the rest of the code can be tested without root.
package system

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// Result is what a finished command produced. A non-zero Code is not an error.
type Result struct {
	Stdout string
	Stderr string
	Code   int
}

// Runner runs a command and returns its output and exit code. err is non-nil
// only when the command could not be run at all (e.g. binary not found).
type Runner interface {
	Run(name string, args ...string) (Result, error)
}

// Exec runs real commands on the host, with LC_ALL=C so output is parseable.
type Exec struct{}

func (Exec) Run(name string, args ...string) (Result, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.Code = exitErr.ExitCode()
		return res, nil
	}
	return res, err
}

// Streamer starts a long-running command (journalctl -f) and hands back its
// stdout and stderr as they are written; Close stops the command. Runners
// that can stream implement it next to Run.
type Streamer interface {
	Stream(name string, args ...string) (io.ReadCloser, error)
}

func (Exec) Stream(name string, args ...string) (io.ReadCloser, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdout, cmd.Stderr = w, w // one pipe, so lines keep their order
	err = cmd.Start()
	w.Close() // the command holds its own copy; reads end when it exits
	if err != nil {
		out.Close()
		return nil, err
	}
	return stream{out, cmd}, nil
}

// stream is a running command's stdout and stderr; Close kills the command
// and reaps it.
type stream struct {
	*os.File
	cmd *exec.Cmd
}

func (s stream) Close() error {
	s.cmd.Process.Kill()
	s.cmd.Wait() // "signal: killed" is the expected outcome, not an error
	return s.File.Close()
}

// Fake is a scripted Runner for tests. Results is keyed by the full command
// line ("systemctl is-enabled ssh.socket"); unscripted commands fail as if the
// binary were missing. Streams scripts Stream the same way. Every call is
// appended to Calls.
type Fake struct {
	Results map[string]Result
	Streams map[string]io.ReadCloser
	Calls   []string
}

func (f *Fake) Stream(name string, args ...string) (io.ReadCloser, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	f.Calls = append(f.Calls, line)
	rc, ok := f.Streams[line]
	if !ok {
		return nil, fmt.Errorf("fake: %q: %w", line, exec.ErrNotFound)
	}
	return rc, nil
}

func (f *Fake) Run(name string, args ...string) (Result, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	f.Calls = append(f.Calls, line)
	res, ok := f.Results[line]
	if !ok {
		return Result{}, fmt.Errorf("fake: %q: %w", line, exec.ErrNotFound)
	}
	return res, nil
}
