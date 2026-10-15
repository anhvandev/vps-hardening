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
	"sync"
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

func (e Exec) Run(name string, args ...string) (Result, error) {
	return e.RunLive(io.Discard, name, args...)
}

// LiveRunner is a Runner that can also copy a command's stdout and stderr to
// w as they are written (a Task's live output). Runners that can implement
// it next to Run.
type LiveRunner interface {
	RunLive(w io.Writer, name string, args ...string) (Result, error)
}

func (Exec) RunLive(w io.Writer, name string, args ...string) (Result, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	var stdout, stderr bytes.Buffer
	sw := &syncWriter{w: w} // stdout and stderr are copied by two goroutines
	cmd.Stdout, cmd.Stderr = io.MultiWriter(&stdout, sw), io.MultiWriter(&stderr, sw)
	err := cmd.Run()
	res := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.Code = exitErr.ExitCode()
		return res, nil
	}
	return res, err
}

type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// Streamer starts a long-running command (journalctl -f) and hands back its
// stdout as it is written; Close stops the command. Runners that can stream
// implement it next to Run.
type Streamer interface {
	Stream(name string, args ...string) (io.ReadCloser, error)
}

func (Exec) Stream(name string, args ...string) (io.ReadCloser, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return stream{out, cmd}, nil
}

// stream is a running command's stdout; Close kills the command and reaps it.
type stream struct {
	io.Reader
	cmd *exec.Cmd
}

func (s stream) Close() error {
	s.cmd.Process.Kill()
	s.cmd.Wait() // "signal: killed" is the expected outcome, not an error
	return nil
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
