package disk

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/anhvandev/vpsctl/internal/system"
)

// Cleanup is one fixed way to reclaim space, read before it runs.
type Cleanup struct {
	Name        string
	Detail      string // what it removes, when that is a short list (old kernels)
	Reclaimable int64  // bytes it would free
	Why         string // set when it can't run: the reason; Run is nil then
	Dangerous   bool   // wants the dangerous confirm
	Run         func(r system.Runner) error
}

var journalUsage = regexp.MustCompile(`take up ([\d.]+)([BKMGT])`)

// Journal vacuums the systemd journal down to keepMB megabytes.
func Journal(r system.Runner, keepMB int) Cleanup {
	c := Cleanup{Name: fmt.Sprintf("Vacuum journal to %d MB", keepMB)}
	out, err := run(r, "journalctl", "--disk-usage")
	m := journalUsage.FindStringSubmatch(out)
	if err != nil || m == nil {
		c.Why = "journal size unknown"
		return c
	}
	n, _ := strconv.ParseFloat(m[1], 64)
	used := int64(n * float64(int64(1)<<(10*strings.Index("BKMGT", m[2]))))
	c.Reclaimable = max(used-int64(keepMB)<<20, 0)
	c.Run = func(r system.Runner) error {
		_, err := run(r, "journalctl", fmt.Sprintf("--vacuum-size=%dM", keepMB))
		return err
	}
	return c
}

// PackageCache empties the package manager's download cache under root.
func PackageCache(r system.Runner, root, pkgMgr string) Cleanup {
	dir, clean := map[string]string{"apt": "/var/cache/apt/archives", "dnf": "/var/cache/dnf"}[pkgMgr],
		map[string][]string{"apt": {"apt-get", "clean"}, "dnf": {"dnf", "clean", "all"}}[pkgMgr]
	c := Cleanup{Name: "Clean " + pkgMgr + " cache"}
	if dir == "" {
		c.Why = "unsupported package manager"
		return c
	}
	filepath.WalkDir(filepath.Join(root, dir), func(_ string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if info, err := d.Info(); err == nil {
				c.Reclaimable += info.Size()
			}
		}
		return nil // an unreadable part counts as empty
	})
	c.Run = func(r system.Runner) error {
		_, err := run(r, clean[0], clean[1:]...)
		return err
	}
	return c
}

// OldKernels removes installed kernels older than the running one, keeping
// the newest of those as a fallback. The running kernel and any newer one
// (installed, waiting for a reboot) are never removed.
func OldKernels(r system.Runner, pkgMgr string) Cleanup {
	c := Cleanup{Name: "Remove old kernels", Dangerous: true}
	running, err := run(r, "uname", "-r")
	running = strings.TrimSpace(running)
	if err != nil || running == "" {
		c.Why = "running kernel unknown"
		return c
	}
	ks, err := installedKernels(r, pkgMgr)
	if err != nil {
		c.Why = err.Error()
		return c
	}
	var old []kernel
	for _, k := range ks {
		if compareVersions(k.version, running) < 0 {
			old = append(old, k)
		}
	}
	var versions, pkgs []string
	for _, k := range old[:max(len(old)-1, 0)] {
		versions, pkgs, c.Reclaimable = append(versions, k.version), append(pkgs, k.pkgs...), c.Reclaimable+k.size
	}
	c.Detail = strings.Join(versions, ", ")
	c.Run = func(r system.Runner) error {
		now, err := run(r, "uname", "-r")
		if now = strings.TrimSpace(now); err != nil || now == "" || slices.Contains(versions, now) {
			return fmt.Errorf("refused: running kernel %q would be removed", now)
		}
		if pkgMgr == "apt" {
			_, err = run(r, "env", append([]string{"DEBIAN_FRONTEND=noninteractive", "apt-get", "purge", "-y"}, pkgs...)...)
		} else {
			_, err = run(r, "dnf", append([]string{"remove", "-y"}, pkgs...)...)
		}
		return err
	}
	return c
}

// kernel is one installed kernel version and the packages that belong to it.
type kernel struct {
	version string
	pkgs    []string
	size    int64 // bytes
}

// installedKernels lists the installed kernels, oldest first.
func installedKernels(r system.Runner, pkgMgr string) ([]kernel, error) {
	byVersion := map[string]*kernel{}
	var images []string // versions with a kernel image
	add := func(version, pkg string, size int64, image bool) {
		k := byVersion[version]
		if k == nil {
			k = &kernel{version: version}
			byVersion[version] = k
		}
		k.pkgs, k.size = append(k.pkgs, pkg), k.size+size
		if image && !slices.Contains(images, version) {
			images = append(images, version)
		}
	}
	switch pkgMgr {
	case "apt":
		// rc 1 when a pattern matches nothing; the lines are still usable.
		res, err := r.Run("dpkg-query", "-W", `-f=${db:Status-Abbrev}\t${Package}\t${Installed-Size}\n`, "linux-*")
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(res.Stdout, "\n") {
			f := strings.Split(line, "\t")
			if len(f) != 3 || !strings.HasPrefix(f[0], "ii") {
				continue
			}
			kib, _ := strconv.ParseInt(f[2], 10, 64)
			for _, p := range []string{"linux-image-unsigned-", "linux-image-", "linux-modules-extra-", "linux-modules-", "linux-headers-"} {
				if v, ok := strings.CutPrefix(f[1], p); ok && v != "" && unicode.IsDigit(rune(v[0])) {
					add(v, f[1], kib*1024, strings.HasPrefix(p, "linux-image-"))
					break
				}
			}
		}
	case "dnf":
		out, err := run(r, "rpm", "-qa", "--qf", `%{NAME}\t%{VERSION}-%{RELEASE}.%{ARCH}\t%{SIZE}\n`, "kernel*")
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Split(line, "\t")
			if len(f) != 3 || !slices.Contains([]string{"kernel", "kernel-core", "kernel-modules", "kernel-modules-core", "kernel-modules-extra", "kernel-devel"}, f[0]) {
				continue
			}
			b, _ := strconv.ParseInt(f[2], 10, 64)
			add(f[1], f[0]+"-"+f[1], b, f[0] == "kernel-core")
		}
	default:
		return nil, errors.New("unsupported package manager")
	}
	var ks []kernel
	for _, v := range images {
		ks = append(ks, *byVersion[v])
	}
	slices.SortFunc(ks, func(a, b kernel) int { return compareVersions(a.version, b.version) })
	return ks, nil
}

// compareVersions orders kernel versions, comparing runs of digits as
// numbers: 6.8.0-9 < 6.8.0-38 < 6.8.0-100.
func compareVersions(a, b string) int {
	ta, tb := versionParts(a), versionParts(b)
	for i := range min(len(ta), len(tb)) {
		x, y := ta[i], tb[i]
		if unicode.IsDigit(rune(x[0])) && unicode.IsDigit(rune(y[0])) {
			x, y = strings.TrimLeft(x, "0"), strings.TrimLeft(y, "0")
			if len(x) != len(y) {
				return len(x) - len(y)
			}
		}
		if c := strings.Compare(x, y); c != 0 {
			return c
		}
	}
	return len(ta) - len(tb)
}

// versionParts splits v into runs of digits and runs of other characters.
func versionParts(v string) []string {
	var parts []string
	for i := 0; i < len(v); {
		j := i + 1
		for j < len(v) && unicode.IsDigit(rune(v[j])) == unicode.IsDigit(rune(v[i])) {
			j++
		}
		parts, i = append(parts, v[i:j]), j
	}
	return parts
}
