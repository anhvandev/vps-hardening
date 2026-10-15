package system

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExecCapturesStdoutStderrAndExitCode(t *testing.T) {
	res, err := Exec{}.Run("sh", "-c", "echo out; echo err >&2; exit 3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Stdout != "out\n" || res.Stderr != "err\n" || res.Code != 3 {
		t.Fatalf("got %+v", res)
	}
}

// RunLive copies stdout and stderr to w as they are written, and still
// returns them apart.
func TestExecRunLive(t *testing.T) {
	seen := filepath.Join(t.TempDir(), "seen")
	r, w := io.Pipe()
	done := make(chan Result)
	go func() {
		// prints "seen" only if "first" reached w while it still ran
		res, _ := Exec{}.RunLive(w, "sh", "-c", `echo first; i=0; while [ ! -e "$0" ] && [ $i -lt 300 ]; do sleep 0.01; i=$((i+1)); done; [ -e "$0" ] && echo seen; echo err >&2; exit 2`, seen)
		w.Close()
		done <- res
	}()
	br := bufio.NewReader(r)
	if line, _ := br.ReadString('\n'); line != "first\n" {
		t.Fatalf("read %q", line)
	}
	os.WriteFile(seen, nil, 0o600)
	go io.Copy(io.Discard, br)
	res := <-done
	if res.Stdout != "first\nseen\n" || res.Stderr != "err\n" || res.Code != 2 {
		t.Fatalf("got %+v", res)
	}
}

func TestExecMissingBinaryIsError(t *testing.T) {
	if _, err := (Exec{}).Run("vpsctl-no-such-binary"); err == nil {
		t.Fatal("expected error for missing binary")
	}
}

// Close stops a stream that would otherwise run for a long time.
func TestExecStreamReadsUntilClosed(t *testing.T) {
	rc, err := Exec{}.Stream("sh", "-c", "echo first; exec sleep 60")
	if err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(rc).ReadString('\n')
	if err != nil || line != "first\n" {
		t.Fatalf("read %q, %v", line, err)
	}
	start := time.Now()
	if err := rc.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("close did not stop the process")
	}
}

func TestFakeStreamReturnsScriptedReader(t *testing.T) {
	f := &Fake{Streams: map[string]io.ReadCloser{"journalctl -f": io.NopCloser(strings.NewReader("a\n"))}}
	rc, err := f.Stream("journalctl", "-f")
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(rc); string(b) != "a\n" {
		t.Errorf("read %q", b)
	}
	if _, err := f.Stream("journalctl"); err == nil {
		t.Error("unscripted stream must return an error")
	}
	if len(f.Calls) != 2 || f.Calls[0] != "journalctl -f" {
		t.Errorf("calls: %q", f.Calls)
	}
}

func TestFakeReturnsScriptedResultAndRecordsCalls(t *testing.T) {
	f := &Fake{Results: map[string]Result{"systemctl is-enabled ssh.socket": {Stdout: "enabled\n"}}}
	res, err := f.Run("systemctl", "is-enabled", "ssh.socket")
	if err != nil || res.Stdout != "enabled\n" {
		t.Fatalf("got %+v, %v", res, err)
	}
	if _, err := f.Run("getenforce"); err == nil {
		t.Fatal("unscripted command must return an error (not found)")
	}
	if len(f.Calls) != 2 || f.Calls[1] != "getenforce" {
		t.Fatalf("calls: %q", f.Calls)
	}
}
