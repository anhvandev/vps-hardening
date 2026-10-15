package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Spec: a second session sees "locked by <user> (pid N)".
func TestSecondLockSeesHolder(t *testing.T) {
	t.Setenv("SUDO_USER", "alice")
	p := filepath.Join(t.TempDir(), "vpsctl.lock")
	lk, err := lock(p)
	if err != nil {
		t.Fatal(err)
	}
	_, err = lock(p)
	if want := fmt.Sprintf("locked by alice (pid %d)", os.Getpid()); err == nil || err.Error() != want {
		t.Fatalf("second lock: %v, want %q", err, want)
	}
	lk.Close()
	lk, err = lock(p)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	lk.Close()
}
