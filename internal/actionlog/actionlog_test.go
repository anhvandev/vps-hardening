package actionlog

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBusyLockReportsHolder(t *testing.T) {
	t.Setenv("SUDO_USER", "alice")
	p := filepath.Join(t.TempDir(), "vpsctl.lock")
	lk, err := Lock(p)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Lock(p)
	if want := fmt.Sprintf("locked by alice (pid %d)", os.Getpid()); err == nil || err.Error() != want {
		t.Fatalf("second lock: %v, want %q", err, want)
	}
	lk.Close()
	lk, err = Lock(p)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	lk.Close()
}

func TestAppendWritesOneLinePerAction(t *testing.T) {
	t.Setenv("SUDO_USER", "alice")
	p := filepath.Join(t.TempDir(), "vpsctl", "actions.log") // dir does not exist yet
	if err := Append(p, "harden --user bob", "ok"); err != nil {
		t.Fatal(err)
	}
	if err := Append(p, "firewall open 8080/tcp", "failed"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	want := []string{"alice harden --user bob: ok", "alice firewall open 8080/tcp: failed"}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines %q, want %d", len(lines), lines, len(want))
	}
	for i, l := range lines {
		ts, rest, _ := strings.Cut(l, " ")
		if _, err := time.Parse(time.RFC3339, ts); err != nil {
			t.Errorf("line %d: time %q: %v", i, ts, err)
		}
		if rest != want[i] {
			t.Errorf("line %d: %q, want %q", i, rest, want[i])
		}
	}
}

// Holder peeks at the lock without taking it: "" when free (or never
// created), the holder while held, and the lock stays takeable after a peek.
func TestHolderPeeksAtTheLock(t *testing.T) {
	t.Setenv("SUDO_USER", "alice")
	p := filepath.Join(t.TempDir(), "vpsctl.lock")
	if h := Holder(p); h != "" {
		t.Errorf("no lock file: holder %q", h)
	}
	if _, err := os.Stat(p); err == nil {
		t.Error("Holder created the lock file")
	}
	lk, err := Lock(p)
	if err != nil {
		t.Fatal(err)
	}
	if h, want := Holder(p), fmt.Sprintf("alice (pid %d)", os.Getpid()); h != want {
		t.Errorf("held: holder %q, want %q", h, want)
	}
	lk.Close()
	if h := Holder(p); h != "" {
		t.Errorf("released: holder %q", h)
	}
	lk, err = Lock(p)
	if err != nil {
		t.Fatalf("lock after peek: %v", err)
	}
	lk.Close()
}

func TestLockHolderIsRootWithoutSudoUser(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	p := filepath.Join(t.TempDir(), "vpsctl.lock")
	lk, err := Lock(p)
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Close()
	_, err = Lock(p)
	if want := fmt.Sprintf("locked by root (pid %d)", os.Getpid()); err == nil || err.Error() != want {
		t.Fatalf("second lock: %v, want %q", err, want)
	}
}
