package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
	"unsafe"
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

// openPTY returns a pseudo-terminal pair (master, slave) using only stdlib ioctls.
func openPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no /dev/ptmx: %v", err)
	}
	t.Cleanup(func() { m.Close() })
	var unlock int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); e != 0 {
		t.Fatal(e)
	}
	var n uint32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); e != 0 {
		t.Fatal(e)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return m, s
}

// A stray Enter typed while harden was busy must not answer the Verify Gate.
func TestAskIgnoresTypeahead(t *testing.T) {
	m, s := openPTY(t)
	go io.Copy(io.Discard, m) // drain echo/prompt so writes to s never block
	m.Write([]byte("\r"))     // typeahead before the question
	time.Sleep(100 * time.Millisecond)

	got := make(chan bool, 1)
	go func() {
		ok, err := ask(s, "Did the NEW login work?")
		if err != nil {
			t.Error(err)
		}
		got <- ok
	}()
	time.Sleep(100 * time.Millisecond)
	m.Write([]byte("y\r"))
	select {
	case ok := <-got:
		if !ok {
			t.Fatal("typeahead answered the gate; want the later 'y'")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ask did not return")
	}
}
