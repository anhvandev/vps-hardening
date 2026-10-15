// Package disk reads filesystem usage, finds the largest directories under a
// mount, and offers fixed cleanups (journal, package cache, old kernels),
// each with the space it would reclaim. It never deletes arbitrary paths.
package disk

import (
	"bufio"
	"cmp"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/anhvandev/vpsctl/internal/system"
)

// Filesystem is one mounted filesystem's usage, in bytes.
type Filesystem struct {
	Mount, Type string
	Size, Used  int64
}

// Filesystems lists real mounted filesystems (pseudo ones like tmpfs left out).
func Filesystems(r system.Runner) ([]Filesystem, error) {
	res, err := run(r, "df", "-B1", "--output=source,fstype,size,used,avail,target",
		"-x", "tmpfs", "-x", "devtmpfs", "-x", "overlay", "-x", "squashfs", "-x", "efivarfs")
	if err != nil {
		return nil, err
	}
	var fss []Filesystem
	for _, line := range strings.Split(res, "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		size, _ := strconv.ParseInt(f[2], 10, 64)
		used, _ := strconv.ParseInt(f[3], 10, 64)
		fss = append(fss, Filesystem{Mount: strings.Join(f[5:], " "), Type: f[1], Size: size, Used: used})
	}
	return fss, nil
}

// ScanDepth is how deep the largest-directory scan looks below the mount.
const ScanDepth = 3

// Dir is a directory and the bytes under it.
type Dir struct {
	Path string
	Size int64
}

// Scan starts measuring the directories under mount, ScanDepth deep and on
// that filesystem only (so /proc, /sys and other mounts are skipped). Read
// the result with Largest; closing the stream stops the scan.
func Scan(r system.Runner, mount string) (io.ReadCloser, error) {
	s, ok := r.(system.Streamer)
	if !ok {
		return nil, errors.New("scan not supported by this runner")
	}
	return s.Stream("du", "-x", "-B1", "-d", strconv.Itoa(ScanDepth), mount)
}

// Largest reads a scan to its end and returns its n biggest directories,
// biggest first, leaving out mount itself.
func Largest(scan io.Reader, mount string, n int) ([]Dir, error) {
	var dirs []Dir
	sc := bufio.NewScanner(scan)
	for sc.Scan() {
		size, path, ok := strings.Cut(sc.Text(), "\t")
		b, err := strconv.ParseInt(size, 10, 64)
		if ok && err == nil && path != mount {
			dirs = append(dirs, Dir{path, b})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	slices.SortStableFunc(dirs, func(a, b Dir) int { return cmp.Compare(b.Size, a.Size) })
	return dirs[:min(n, len(dirs))], nil
}

// run runs name args, returning stdout or an error carrying stderr.
func run(r system.Runner, name string, args ...string) (string, error) {
	res, err := r.Run(name, args...)
	if err != nil {
		return "", err
	}
	if res.Code != 0 {
		return res.Stdout, fmt.Errorf("%s: exit %d: %s", name, res.Code, strings.TrimSpace(res.Stderr))
	}
	return res.Stdout, nil
}
