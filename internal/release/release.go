// Package release fetches vpsctl releases from GitHub: the latest tag, and
// the binary + sha256sums.txt that self-update verifies (fail closed) before
// replacing the installed binary. Asset names match install.sh.
package release

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// BaseURL is the GitHub releases page of vpsctl.
const BaseURL = "https://github.com/anhvandev/vpsctl/releases"

var client = &http.Client{Timeout: 5 * time.Minute}

// Latest returns the tag of the latest release under base, read from where
// base/latest redirects (base/tag/<tag>).
func Latest(base string) (string, error) {
	resp, err := client.Get(base + "/latest")
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	dir, tag := path.Split(resp.Request.URL.Path)
	if resp.StatusCode != http.StatusOK || !strings.HasSuffix(dir, "/tag/") || tag == "" {
		return "", fmt.Errorf("no latest release at %s (HTTP %d)", base, resp.StatusCode)
	}
	return tag, nil
}

// Update replaces the binary at exe with the latest release for this
// architecture and returns the latest tag. If current is already the latest
// it does nothing. Any download failure, missing checksum or mismatch
// returns an error and leaves exe untouched.
func Update(base, current, exe string) (string, error) {
	tag, err := Latest(base)
	if err != nil || tag == current {
		return tag, err
	}
	asset := "vpsctl-linux-" + runtime.GOARCH
	bin, err := fetch(base + "/download/" + tag + "/" + asset)
	if err != nil {
		return "", err
	}
	sums, err := fetch(base + "/download/" + tag + "/sha256sums.txt")
	if err != nil {
		return "", err
	}
	want := checksum(string(sums), asset)
	if want == "" {
		return "", fmt.Errorf("no checksum for %s in sha256sums.txt", asset)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(bin)); got != want {
		return "", fmt.Errorf("checksum mismatch for %s (want %s, got %s)", asset, want, got)
	}

	// Write next to exe, then rename over it: atomic on the same filesystem.
	f, err := os.CreateTemp(filepath.Dir(exe), ".vpsctl-update-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name()) // no-op after a successful rename
	_, err = f.Write(bin)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(f.Name(), 0o755)
	}
	if err == nil {
		err = os.Rename(f.Name(), exe)
	}
	if err != nil {
		return "", err
	}
	return tag, nil
}

func fetch(url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// checksum finds name's hash in sha256sum output ("<hash>  name" or "<hash> *name").
func checksum(sums, name string) string {
	for line := range strings.Lines(sums) {
		if f := strings.Fields(line); len(f) == 2 && (f[1] == name || f[1] == "*"+name) {
			return f[0]
		}
	}
	return ""
}
