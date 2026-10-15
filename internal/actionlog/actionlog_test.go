package actionlog

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
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
