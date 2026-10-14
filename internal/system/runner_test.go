package system

import "testing"

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
