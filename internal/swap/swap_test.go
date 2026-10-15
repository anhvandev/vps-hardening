package swap

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/anhvandev/vpsctl/internal/system"
)

const gib = 1 << 30

// host is a temp root with /proc/swaps, /proc/meminfo and /etc/fstab.
func host(t *testing.T, swaps, meminfo, fstab string) string {
	t.Helper()
	root := t.TempDir()
	for p, s := range map[string]string{"/proc/swaps": swaps, "/proc/meminfo": meminfo, "/etc/fstab": fstab} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func fstab(t *testing.T, root string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "/etc/fstab"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const (
	header   = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
	noSwap   = header
	ownSwap  = header + "/vpsctl.swap                            file\t\t2097148\t\t1048576\t\t-2\n" // 1 GiB used
	partSwap = header + "/dev/vda2                               partition\t1048572\t\t0\t\t-3\n"
	mem2G    = "MemTotal:        2014000 kB\nMemFree:          300000 kB\nMemAvailable:     524288 kB\n" // 512 MiB free
	mem8G    = "MemTotal:        8000000 kB\nMemAvailable:    4194304 kB\n"
	tab      = "UUID=abc / ext4 defaults 0 1\n"
)

func TestReadListsSwapAndRAM(t *testing.T) {
	s, err := Read(host(t, partSwap+"/vpsctl.swap file 2097148 1048576 -2\n", mem2G, tab))
	if err != nil {
		t.Fatal(err)
	}
	want := []Area{{"/dev/vda2", "partition", 1048572 << 10, 0}, {"/vpsctl.swap", "file", 2097148 << 10, gib}}
	if !slices.Equal(s.Areas, want) || s.RAM != 2014000<<10 || s.Available != 512<<20 {
		t.Errorf("Read = %+v", s)
	}
	if own, ok := s.Own(); !ok || own.Name != File {
		t.Errorf("Own = %v, %v", own, ok)
	}
	if s.Suggested() != 2*gib {
		t.Errorf("Suggested = %d, want RAM rounded to 2 GiB", s.Suggested())
	}
	if s, _ := Read(host(t, noSwap, mem8G, tab)); len(s.Areas) != 0 || s.Suggested() != 4*gib {
		t.Errorf("no swap, 8 GB RAM: %+v, suggested %d (max 4 GiB)", s, s.Suggested())
	}
}

// Create checks the disk first, then allocates, enables and persists the
// swapfile; fstab keeps its other lines.
func TestCreate(t *testing.T) {
	root := host(t, noSwap, mem2G, tab)
	f := &system.Fake{Results: map[string]system.Result{
		"df -B1 --output=avail /":              {Stdout: "    Avail\n10737418240\n"},
		"rm -f /vpsctl.swap":                   {},
		"fallocate -l 2147483648 /vpsctl.swap": {},
		"chmod 600 /vpsctl.swap":               {},
		"mkswap /vpsctl.swap":                  {Stdout: "Setting up swapspace version 1\n"},
		"swapon /vpsctl.swap":                  {},
	}}
	if err := Create(f, root, 2*gib, false); err != nil {
		t.Fatal(err)
	}
	want := []string{"df -B1 --output=avail /", "rm -f /vpsctl.swap", "fallocate -l 2147483648 /vpsctl.swap",
		"chmod 600 /vpsctl.swap", "mkswap /vpsctl.swap", "swapon /vpsctl.swap"}
	if !slices.Equal(f.Calls, want) {
		t.Errorf("calls = %q", f.Calls)
	}
	if got := fstab(t, root); got != tab+"/vpsctl.swap none swap sw 0 0\n" {
		t.Errorf("fstab = %q", got)
	}
}

// Without fallocate support (some filesystems) the file is written with dd.
func TestCreateFallsBackToDD(t *testing.T) {
	root := host(t, noSwap, mem2G, "")
	f := &system.Fake{Results: map[string]system.Result{
		"df -B1 --output=avail /":                          {Stdout: "Avail\n10737418240\n"},
		"rm -f /vpsctl.swap":                               {},
		"fallocate -l 1073741824 /vpsctl.swap":             {Code: 1, Stderr: "fallocate: Operation not supported"},
		"dd if=/dev/zero of=/vpsctl.swap bs=1M count=1024": {},
		"chmod 600 /vpsctl.swap":                           {},
		"mkswap /vpsctl.swap":                              {},
		"swapon /vpsctl.swap":                              {},
	}}
	if err := Create(f, root, gib, false); err != nil {
		t.Fatal(err)
	}
	if got := fstab(t, root); got != "/vpsctl.swap none swap sw 0 0\n" {
		t.Errorf("fstab = %q", got)
	}
}

// With SELinux on, the swapfile gets the swapfile_t type before swapon
// (else swapon is denied); a resize labels the new file.
func TestSwapfileLabelledOnSELinux(t *testing.T) {
	root := host(t, noSwap, mem2G, tab)
	f := &system.Fake{Results: map[string]system.Result{
		"df -B1 --output=avail /":              {Stdout: "Avail\n10737418240\n"},
		"rm -f /vpsctl.swap":                   {},
		"fallocate -l 1073741824 /vpsctl.swap": {},
		"chmod 600 /vpsctl.swap":               {},
		"mkswap /vpsctl.swap":                  {},
		"chcon -t swapfile_t /vpsctl.swap":     {},
		"swapon /vpsctl.swap":                  {},
	}}
	if err := Create(f, root, gib, true); err != nil {
		t.Fatal(err)
	}
	if i := slices.Index(f.Calls, "chcon -t swapfile_t /vpsctl.swap"); i < 0 || f.Calls[i+1] != "swapon /vpsctl.swap" {
		t.Errorf("calls = %q", f.Calls)
	}

	root, f = resizeHost(t)
	f.Results["chcon -t swapfile_t /vpsctl.swap.new"] = system.Result{}
	if err := Resize(f, root, 3*gib, true); err != nil {
		t.Fatal(err)
	}
	if i := slices.Index(f.Calls, "chcon -t swapfile_t /vpsctl.swap.new"); i < 0 || i > slices.Index(f.Calls, "swapon /vpsctl.swap") {
		t.Errorf("calls = %q", f.Calls)
	}
}

// Not enough free disk: refused before anything is written.
func TestCreateRefusedWithoutDisk(t *testing.T) {
	root := host(t, noSwap, mem2G, tab)
	f := &system.Fake{Results: map[string]system.Result{"df -B1 --output=avail /": {Stdout: "Avail\n2147483648\n"}}}
	err := Create(f, root, 2*gib, false)
	if err == nil || !strings.HasPrefix(err.Error(), "refused: not enough free disk") {
		t.Fatalf("err = %v", err)
	}
	if !slices.Equal(f.Calls, []string{"df -B1 --output=avail /"}) || fstab(t, root) != tab {
		t.Errorf("wrote something: calls %q, fstab %q", f.Calls, fstab(t, root))
	}
}

func TestCreateRefusedWhenOwnSwapfileExists(t *testing.T) {
	f := &system.Fake{}
	if err := Create(f, host(t, ownSwap, mem2G, tab), gib, false); err == nil || len(f.Calls) != 0 {
		t.Errorf("err = %v, calls %q", err, f.Calls)
	}
}

// Remove turns the swapfile off, drops its fstab line, then deletes it.
func TestRemove(t *testing.T) {
	root := host(t, partSwap+"/vpsctl.swap file 2097148 0 -2\n", mem2G, "/dev/vda2 none swap sw 0 0\n"+tab+"/vpsctl.swap none swap sw 0 0\n")
	f := &system.Fake{Results: map[string]system.Result{"swapoff /vpsctl.swap": {}, "rm -f /vpsctl.swap": {}}}
	if err := Remove(f, root); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.Calls, []string{"swapoff /vpsctl.swap", "rm -f /vpsctl.swap"}) {
		t.Errorf("calls = %q", f.Calls)
	}
	if got := fstab(t, root); got != "/dev/vda2 none swap sw 0 0\n"+tab {
		t.Errorf("fstab = %q (the partition's line must stay)", got)
	}
}

// Swap in use beyond the free RAM: remove and resize are refused, nothing runs.
func TestRemoveAndResizeRefusedOnOOMRisk(t *testing.T) {
	line := "/vpsctl.swap none swap sw 0 0\n"
	root := host(t, ownSwap, mem2G, tab+line) // 1 GiB used, 512 MiB free RAM
	f := &system.Fake{}
	for name, err := range map[string]error{"remove": Remove(f, root), "resize": Resize(f, root, gib, false)} {
		if err == nil || err.Error() != "refused: 1.0 GiB of swap in use exceeds 512 MiB free RAM (OOM risk)" {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if len(f.Calls) != 0 || fstab(t, root) != tab+line {
		t.Errorf("changed something: %q", f.Calls)
	}
}

// resizeHost is an 8 GB machine with vpsctl's 2 GiB swapfile, 4 GiB free
// on disk, where every command of a resize to 3 GiB works.
func resizeHost(t *testing.T) (string, *system.Fake) {
	root := host(t, ownSwap, mem8G, tab+"/vpsctl.swap none swap sw 0 0\n")
	f := &system.Fake{Results: map[string]system.Result{"df -B1 --output=avail /": {Stdout: "Avail\n4294967296\n"}}}
	for _, c := range resizeCalls {
		f.Results[c] = system.Result{}
	}
	return root, f
}

var resizeCalls = []string{"rm -f /vpsctl.swap.new", "fallocate -l 3221225472 /vpsctl.swap.new", "chmod 600 /vpsctl.swap.new",
	"mkswap /vpsctl.swap.new", "swapoff /vpsctl.swap", "mv -f /vpsctl.swap /vpsctl.swap.old",
	"mv -f /vpsctl.swap.new /vpsctl.swap", "swapon /vpsctl.swap", "rm -f /vpsctl.swap.old"}

// Resize builds the new swapfile beside the old one first, then switches:
// the old one is off only once the new one is ready. Both are on disk for a
// moment, so the old file's space doesn't count as free.
func TestResize(t *testing.T) {
	root, f := resizeHost(t)
	if err := Resize(f, root, 3*gib, false); err != nil {
		t.Fatal(err)
	}
	if want := append([]string{"df -B1 --output=avail /"}, resizeCalls...); !slices.Equal(f.Calls, want) {
		t.Errorf("calls\n got %q\nwant %q", f.Calls, want)
	}
	if got := fstab(t, root); got != tab+"/vpsctl.swap none swap sw 0 0\n" {
		t.Errorf("fstab = %q", got)
	}
	f.Calls = nil
	if err := Resize(f, root, 4*gib, false); err == nil || len(f.Calls) != 1 {
		t.Errorf("4 GiB with 4 GiB free: err %v, calls %q", err, f.Calls)
	}
}

// failFirst fails the first run of cmd, as if the new swapfile could not be
// turned on; later runs (turning the old one back on) work.
type failFirst struct {
	*system.Fake
	cmd    string
	failed bool
}

func (r *failFirst) Run(name string, args ...string) (system.Result, error) {
	res, err := r.Fake.Run(name, args...)
	if !r.failed && strings.Join(append([]string{name}, args...), " ") == r.cmd {
		r.failed = true
		return system.Result{Code: 255, Stderr: "swapon failed"}, nil
	}
	return res, err
}

// A failed resize keeps the old swapfile on: before the switch the new
// file is just removed; after it, the old file is put back and turned on.
func TestResizeFailureKeepsOldSwap(t *testing.T) {
	for _, c := range []struct {
		fail string
		tail []string // the calls after the failing one
	}{
		{"mkswap /vpsctl.swap.new", []string{"rm -f /vpsctl.swap.new"}},
		{"swapoff /vpsctl.swap", []string{"rm -f /vpsctl.swap.new"}},
		{"swapon /vpsctl.swap", []string{"mv -f /vpsctl.swap /vpsctl.swap.new", "mv -f /vpsctl.swap.old /vpsctl.swap",
			"swapon /vpsctl.swap", "rm -f /vpsctl.swap.new"}},
	} {
		root, f := resizeHost(t)
		f.Results["mv -f /vpsctl.swap /vpsctl.swap.new"] = system.Result{}
		f.Results["mv -f /vpsctl.swap.old /vpsctl.swap"] = system.Result{}
		r := &failFirst{Fake: f, cmd: c.fail}
		if err := Resize(r, root, 3*gib, false); err == nil {
			t.Errorf("%s failing: no error", c.fail)
		}
		i := slices.Index(f.Calls, c.fail)
		if i < 0 || !slices.Equal(f.Calls[i+1:], c.tail) {
			t.Errorf("%s failing: calls %q", c.fail, f.Calls)
		}
	}
}
