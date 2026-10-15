package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/anhvandev/vpsctl/internal/system"
)

const (
	swapsHeader = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
	partition   = "/dev/vda2 partition 1048572 0 -3\n"
	ownSwapfile = "/vpsctl.swap file 2097148 1048576 -2\n" // 2 GiB, 1 GiB used
	swapLine    = "/vpsctl.swap none swap sw 0 0\n"
)

// swapHost is debianHost (4 GiB RAM, 3 GiB free) with swaps active, fstab
// and 20 GiB free on /.
func swapHost(t *testing.T, swaps, fstab string) *testHost {
	h := debianHost(t)
	h.write("/proc/swaps", swapsHeader+swaps)
	h.write("/etc/fstab", fstab)
	h.write("/run/.keep", "") // the lock lives under /run
	h.fake.Results["df -B1 --output=avail /"] = system.Result{Stdout: "Avail\n21474836480\n"}
	return h
}

// openSwap starts the TUI on h and focuses the Swap screen, loaded once it shows want.
func openSwap(t *testing.T, h *testHost, want string) *teatest.TestModel {
	t.Helper()
	tm := start(h)
	waitFor(t, tm, "RAM")
	tm.Type(menuTo("Swap"))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, want)
	return tm
}

func fstabOf(t *testing.T, h *testHost) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.root, "/etc/fstab"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A partition is listed read-only; the swapfile is created with the
// suggested size (= RAM, 4 GiB here) after a Yes, as a Task, and persisted.
func TestSwapCreate(t *testing.T) {
	h := swapHost(t, partition, "UUID=abc / ext4 defaults 0 1\n")
	for _, c := range []string{"rm -f /vpsctl.swap", "fallocate -l 4294967296 /vpsctl.swap", "chmod 600 /vpsctl.swap", "mkswap /vpsctl.swap", "swapon /vpsctl.swap"} {
		h.fake.Results[c] = system.Result{}
	}
	tm := openSwap(t, h, "read-only")
	tm.Type("a")
	waitFor(t, tm, "suggested = RAM, max 4 GiB")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // the suggested size
	waitFor(t, tm, "Create a 4.0 GiB swapfile?")
	tm.Type("y")
	waitFor(t, tm, "SUMMARY  created 4.0 GiB swapfile")
	v := ctrlCView(t, tm)
	wantAll(t, v, "Done in")

	if got := fstabOf(t, h); got != "UUID=abc / ext4 defaults 0 1\n"+swapLine {
		t.Errorf("fstab = %q", got)
	}
	if log := actionLog(t, h); !strings.Contains(log, "swap create 4.0 GiB: ok") {
		t.Errorf("Task History:\n%s", log)
	}
}

// Too little free disk for the requested size: refused in the form, nothing runs.
func TestSwapCreateRefusedWithoutDisk(t *testing.T) {
	h := swapHost(t, "", "")
	h.fake.Results["df -B1 --output=avail /"] = system.Result{Stdout: "Avail\n1073741824\n"}
	tm := openSwap(t, h, "free RAM")
	tm.Type("a")
	waitFor(t, tm, "suggested = RAM")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "refused: not enough free disk for 4.0 GiB")
	ctrlCView(t, tm)
	if actionLog(t, h) != "" || fstabOf(t, h) != "" {
		t.Errorf("something ran: %q", actionLog(t, h))
	}
}

// Swap in use beyond the free RAM: Remove and Resize are disabled with the reason.
func TestSwapRemoveRefusedOnOOMRisk(t *testing.T) {
	h := swapHost(t, ownSwapfile, swapLine)
	h.write("/proc/meminfo", "MemTotal:        4194304 kB\nMemAvailable:     524288 kB\n")
	tm := openSwap(t, h, "1.0 GiB of swap in use exceeds 512 MiB free RAM (OOM risk)")
	tm.Type("d")
	v := ctrlCView(t, tm)
	if strings.Contains(v, "Type") || actionLog(t, h) != "" {
		t.Errorf("remove was not refused:\n%s", v)
	}
}

// Remove is a dangerous confirm: the swapfile's path must be typed.
func TestSwapRemove(t *testing.T) {
	h := swapHost(t, partition+ownSwapfile, "UUID=abc / ext4 defaults 0 1\n"+swapLine)
	h.fake.Results["swapoff /vpsctl.swap"] = system.Result{}
	h.fake.Results["rm -f /vpsctl.swap"] = system.Result{}
	tm := openSwap(t, h, "read-only")
	tm.Type("d")
	waitFor(t, tm, `Type "/vpsctl.swap"`)
	tm.Type("/vpsctl.swap")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "SUMMARY  removed swapfile")
	ctrlCView(t, tm)
	if got := fstabOf(t, h); got != "UUID=abc / ext4 defaults 0 1\n" {
		t.Errorf("fstab = %q", got)
	}
}

// With no swap, Overview says so and offers Create swap, which opens Swap.
func TestOverviewOffersCreateSwap(t *testing.T) {
	h := swapHost(t, "", "")
	tm := start(h)
	waitFor(t, tm, "[ Create swap ]")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // focus Overview
	waitFor(t, tm, "s create swap")              // reloaded
	tm.Type("s")
	waitFor(t, tm, "free RAM")
	v := ctrlCView(t, tm)
	wantAll(t, v, "+ Create swapfile")
}
