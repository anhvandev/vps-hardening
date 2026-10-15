// Package swap reads the live swap (/proc/swaps) and RAM (/proc/meminfo)
// and manages vpsctl's own swapfile, File: create, resize, remove, kept
// across reboots by one /etc/fstab line. Swap vpsctl didn't create (other
// files, partitions) is only read. Commands go through a system.Runner;
// file paths are under a root ("" in production).
package swap

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/anhvandev/vpsctl/internal/system"
)

// File is vpsctl's swapfile; no other swap is ever touched.
const File = "/vpsctl.swap"

const (
	fstabLine    = File + " none swap sw 0 0"
	margin       = 512 << 20 // free disk left after the swapfile
	maxSuggested = 4 << 30
)

// Area is one active swap area; sizes in bytes. Type is "file" or "partition".
type Area struct {
	Name, Type string
	Size, Used int64
}

// State is the live swap and RAM; RAM and Available in bytes.
type State struct {
	Areas          []Area
	RAM, Available int64
}

// Read reads the active swap areas and the RAM.
func Read(root string) (State, error) {
	var s State
	b, err := os.ReadFile(filepath.Join(root, "/proc/swaps"))
	if err != nil {
		return s, err
	}
	for _, line := range strings.Split(string(b), "\n")[1:] { // after the header
		if f := strings.Fields(line); len(f) >= 4 {
			size, _ := strconv.ParseInt(f[2], 10, 64)
			used, _ := strconv.ParseInt(f[3], 10, 64)
			s.Areas = append(s.Areas, Area{f[0], f[1], size << 10, used << 10})
		}
	}
	if b, err = os.ReadFile(filepath.Join(root, "/proc/meminfo")); err != nil {
		return s, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		kb, _ := strconv.ParseInt(f[1], 10, 64)
		switch f[0] {
		case "MemTotal:":
			s.RAM = kb << 10
		case "MemAvailable:":
			s.Available = kb << 10
		}
	}
	if s.RAM == 0 {
		return s, errors.New("no MemTotal in /proc/meminfo")
	}
	return s, nil
}

// Own is vpsctl's swapfile, if active.
func (s State) Own() (Area, bool) {
	for _, a := range s.Areas {
		if a.Name == File {
			return a, true
		}
	}
	return Area{}, false
}

// Suggested is the swapfile size to offer: RAM rounded to whole GiB, 1 to 4 GiB.
func (s State) Suggested() int64 {
	gib := (s.RAM + 1<<29) >> 30
	return min(max(gib, 1)<<30, maxSuggested)
}

// OffRefusal is why turning vpsctl's swapfile off (remove, resize) is
// refused, nil if it is safe: its pages must fit in the free RAM.
func (s State) OffRefusal() error {
	own, ok := s.Own()
	switch {
	case !ok:
		return errors.New("refused: vpsctl has no swapfile")
	case own.Used > s.Available:
		return fmt.Errorf("refused: %s of swap in use exceeds %s free RAM (OOM risk)", Human(own.Used), Human(s.Available))
	}
	return nil
}

// DiskRefusal is why a swapfile of size bytes doesn't fit in free bytes of
// disk, nil if it fits with a margin to spare.
func DiskRefusal(free, size int64) error {
	if free < size+margin {
		return fmt.Errorf("refused: not enough free disk for %s (%s free, %s kept spare)", Human(size), Human(free), Human(margin))
	}
	return nil
}

// FreeDisk is the free space on / in bytes.
func FreeDisk(r system.Runner) (int64, error) {
	res, err := r.Run("df", "-B1", "--output=avail", "/")
	if err == nil && res.Code != 0 {
		err = fmt.Errorf("df: exit %d: %s", res.Code, strings.TrimSpace(res.Stderr))
	}
	if err != nil {
		return 0, err
	}
	f := strings.Fields(res.Stdout)
	if len(f) != 2 {
		return 0, fmt.Errorf("df: unexpected output %q", res.Stdout)
	}
	return strconv.ParseInt(f[1], 10, 64)
}

// Create makes, enables and persists vpsctl's swapfile of size bytes;
// refused, with nothing written, when it exists or the disk is too full.
func Create(r system.Runner, root string, size int64) error {
	s, err := Read(root)
	if err != nil {
		return err
	}
	if _, ok := s.Own(); ok {
		return errors.New("refused: vpsctl's swapfile exists; resize it instead")
	}
	free, err := FreeDisk(r)
	if err != nil {
		return err
	}
	if err := DiskRefusal(free, size); err != nil {
		return err
	}
	return build(r, root, size)
}

// Resize recreates vpsctl's swapfile at size bytes (off, rewrite, on);
// refused, with nothing changed, on OOM risk or a too full disk.
func Resize(r system.Runner, root string, size int64) error {
	s, err := Read(root)
	if err != nil {
		return err
	}
	if err := s.OffRefusal(); err != nil {
		return err
	}
	free, err := FreeDisk(r)
	if err != nil {
		return err
	}
	own, _ := s.Own()
	if err := DiskRefusal(free+own.Size, size); err != nil { // the old file's space comes back
		return err
	}
	if err := run(r, "swapoff", File); err != nil {
		return err
	}
	return build(r, root, size)
}

// Remove turns vpsctl's swapfile off, drops its fstab line and deletes it;
// refused, with nothing changed, on OOM risk.
func Remove(r system.Runner, root string) error {
	s, err := Read(root)
	if err != nil {
		return err
	}
	if err := s.OffRefusal(); err != nil {
		return err
	}
	if err := run(r, "swapoff", File); err != nil {
		return err
	}
	if err := editFstab(root, false); err != nil {
		return err
	}
	return run(r, "rm", "-f", File)
}

// build writes File (fallocate, or dd where unsupported), enables it and
// adds its fstab line.
func build(r system.Runner, root string, size int64) error {
	if err := run(r, "rm", "-f", File); err != nil { // a stale, inactive one
		return err
	}
	if run(r, "fallocate", "-l", strconv.FormatInt(size, 10), File) != nil {
		if err := run(r, "dd", "if=/dev/zero", "of="+File, "bs=1M", fmt.Sprintf("count=%d", size>>20)); err != nil {
			return err
		}
	}
	for _, c := range [][]string{{"chmod", "600", File}, {"mkswap", File}, {"swapon", File}} {
		if err := run(r, c[0], c[1:]...); err != nil {
			return err
		}
	}
	return editFstab(root, true)
}

// editFstab adds (on) or drops vpsctl's swapfile line, keeping every other line.
func editFstab(root string, on bool) error {
	path := filepath.Join(root, "/etc/fstab")
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var lines []string
	for _, l := range strings.SplitAfter(string(b), "\n") {
		if f := strings.Fields(l); len(f) > 0 && f[0] == File || l == "" {
			continue
		}
		lines = append(lines, l)
	}
	if n := len(lines); n > 0 && !strings.HasSuffix(lines[n-1], "\n") {
		lines[n-1] += "\n"
	}
	if on {
		lines = append(lines, fstabLine+"\n")
	}
	return system.WriteAtomic(path, []byte(strings.Join(lines, "")), 0o644, nil) // never a half-written fstab
}

// run runs a command; a non-zero exit is an error with its stderr.
func run(r system.Runner, name string, args ...string) error {
	res, err := r.Run(name, args...)
	if err == nil && res.Code != 0 {
		err = fmt.Errorf("%s %s: exit %d: %s", name, strings.Join(args, " "), res.Code, strings.TrimSpace(res.Stderr))
	}
	return err
}

// Human is n bytes as "2.0 GiB", "512 MiB" or "0 B".
func Human(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%d MiB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%d KiB", n>>10)
	}
	return fmt.Sprintf("%d B", n)
}
