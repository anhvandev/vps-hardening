package system

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// WriteAtomic replaces the file with its mode, or leaves it untouched (and
// no staged file behind) when prepare fails.
func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := WriteAtomic(p, []byte("new\n"), 0o640, nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "new\n" {
		t.Errorf("content %q", b)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	err := WriteAtomic(p, []byte("bad\n"), 0o640, func(string) error { return errors.New("invalid") })
	if b, _ := os.ReadFile(p); err == nil || string(b) != "new\n" {
		t.Errorf("err %v, content %q", err, b)
	}
	if es, _ := os.ReadDir(dir); len(es) != 1 {
		t.Errorf("left %v", es)
	}
}
