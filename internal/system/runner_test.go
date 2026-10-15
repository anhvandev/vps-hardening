package system

import (
	"bufio"
	"io"
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

// A stream carries stderr too: docker logs writes a container's stderr there.
func TestExecStreamIncludesStderr(t *testing.T) {
	rc, err := Exec{}.Stream("sh", "-c", "echo out; echo err >&2")
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(rc)
	rc.Close()
	if err != nil || string(b) != "out\nerr\n" {
		t.Errorf("read %q, %v", b, err)
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
