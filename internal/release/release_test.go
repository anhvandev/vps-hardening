package release

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

var asset = "vpsctl-linux-" + runtime.GOARCH

// fakeReleases serves a GitHub-like releases tree: /latest redirects to
// /tag/<tag>, /download/<tag>/<file> serves files. A nil file 404s.
func fakeReleases(t *testing.T, tag string, files map[string][]byte) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/releases/tag/"+tag, http.StatusFound)
	})
	mux.HandleFunc("/releases/tag/", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/releases/download/"+tag+"/{file}", func(w http.ResponseWriter, r *http.Request) {
		b, ok := files[r.PathValue("file")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL + "/releases"
}

func sums(name string, b []byte) []byte {
	return fmt.Appendf(nil, "%x  other-file\n%x  %s\n", sha256.Sum256([]byte("x")), sha256.Sum256(b), name)
}

// installed writes the "current binary" and returns its path.
func installed(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "vpsctl")
	if err := os.WriteFile(p, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func content(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestUpdateReplacesBinary(t *testing.T) {
	bin := []byte("new binary")
	base := fakeReleases(t, "v2.1.0", map[string][]byte{asset: bin, "sha256sums.txt": sums(asset, bin)})
	exe := installed(t)

	got, err := Update(base, "v2.0.0", exe)
	if err != nil {
		t.Fatal(err)
	}
	if got != "v2.1.0" {
		t.Fatalf("version %q, want v2.1.0", got)
	}
	if c := content(t, exe); c != "new binary" {
		t.Fatalf("binary %q, want new binary", c)
	}
	if fi, _ := os.Stat(exe); fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v, want 0755", fi.Mode().Perm())
	}
}

// Fail closed: every failure leaves the installed binary untouched and no temp files behind.
func TestUpdateFailureLeavesBinaryUntouched(t *testing.T) {
	bin := []byte("new binary")
	for name, files := range map[string]map[string][]byte{
		"checksum mismatch": {asset: []byte("tampered"), "sha256sums.txt": sums(asset, bin)},
		"no checksum entry": {asset: bin, "sha256sums.txt": sums("vpsctl-linux-mips", bin)},
		"binary missing":    {"sha256sums.txt": sums(asset, bin)},
		"sums missing":      {asset: bin},
	} {
		t.Run(name, func(t *testing.T) {
			base := fakeReleases(t, "v2.1.0", files)
			exe := installed(t)
			if _, err := Update(base, "v2.0.0", exe); err == nil {
				t.Fatal("want error")
			}
			if c := content(t, exe); c != "old binary" {
				t.Fatalf("binary %q, want old binary", c)
			}
			if ents, _ := os.ReadDir(filepath.Dir(exe)); len(ents) != 1 {
				t.Fatalf("leftover files: %v", ents)
			}
		})
	}
}

func TestUpdateAlreadyLatestDoesNothing(t *testing.T) {
	base := fakeReleases(t, "v2.0.0", map[string][]byte{})
	exe := installed(t)
	got, err := Update(base, "v2.0.0", exe)
	if err != nil || got != "v2.0.0" {
		t.Fatalf("Update = %q, %v; want v2.0.0, nil", got, err)
	}
	if c := content(t, exe); c != "old binary" {
		t.Fatalf("binary %q, want old binary", c)
	}
}

func TestLatestOfflineFails(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close() // nothing listening: offline
	if tag, err := Latest(srv.URL + "/releases"); err == nil {
		t.Fatalf("Latest = %q, want error", tag)
	}
}

func TestLatestReadsRedirectTag(t *testing.T) {
	base := fakeReleases(t, "v2.3.4", nil)
	if tag, err := Latest(base); err != nil || tag != "v2.3.4" {
		t.Fatalf("Latest = %q, %v; want v2.3.4", tag, err)
	}
}
