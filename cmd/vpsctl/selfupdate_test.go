package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// self-update takes the global lock and logs "self-update <old> → <new>".
func TestSelfUpdateLocksAndLogs(t *testing.T) {
	bin := []byte("new binary")
	asset := "vpsctl-linux-" + runtime.GOARCH
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/releases/tag/v2.1.0", http.StatusFound)
	})
	mux.HandleFunc("/releases/tag/", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/releases/download/v2.1.0/"+asset, func(w http.ResponseWriter, r *http.Request) { w.Write(bin) })
	mux.HandleFunc("/releases/download/v2.1.0/sha256sums.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%x  %s\n", sha256.Sum256(bin), asset)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	exe, lockPath, logPath := filepath.Join(dir, "vpsctl"), filepath.Join(dir, "lock"), filepath.Join(dir, "actions.log")
	os.WriteFile(exe, []byte("old binary"), 0o755)
	version = "v2.0.0"
	t.Cleanup(func() { version = "dev" })

	lk, err := lock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if code := selfUpdate(srv.URL+"/releases", exe, lockPath, logPath, io.Discard); code != 1 {
		t.Fatalf("with lock held: exit %d, want 1", code)
	}
	if b, _ := os.ReadFile(exe); string(b) != "old binary" {
		t.Fatalf("binary changed while locked: %q", b)
	}
	lk.Close()

	if code := selfUpdate(srv.URL+"/releases", exe, lockPath, logPath, io.Discard); code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
	if b, _ := os.ReadFile(exe); string(b) != "new binary" {
		t.Fatalf("binary %q, want new binary", b)
	}
	log, _ := os.ReadFile(logPath)
	if !strings.Contains(string(log), "self-update v2.0.0 → v2.1.0: ok") {
		t.Fatalf("action log %q, want self-update v2.0.0 → v2.1.0: ok", log)
	}
}
