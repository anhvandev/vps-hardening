package tui

import (
	"io"
	"slices"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/anhvandev/vpsctl/internal/system"
)

const (
	dfDisk      = "df -B1 --output=source,fstype,size,used,avail,target -x tmpfs -x devtmpfs -x overlay -x squashfs -x efivarfs"
	dpkgKernels = `dpkg-query -W -f=${db:Status-Abbrev}\t${Package}\t${Installed-Size}\n linux-*`
)

// diskHost is debianHost with two filesystems, a 1.5 GB journal, 8 bytes
// of apt cache and kernels 6.8.0-38/-41 installed beside the running -45.
func diskHost(t *testing.T) *testHost {
	h := debianHost(t)
	h.write("/run/.keep", "") // the lock lives under /run
	h.write("/var/cache/apt/archives/a.deb", "12345678")
	for cmd, out := range map[string]string{
		dfDisk: "Filesystem     Type  1B-blocks  Used  Avail Mounted on\n" +
			"/dev/vda1      ext4  50000000000 41000000000 9000000000 /\n" +
			"/dev/vda15     vfat  1000000000 200000000 800000000 /boot/efi\n",
		"journalctl --disk-usage": "Archived and active journals take up 1.5G in the file system.\n",
		"uname -r":                "6.8.0-45-generic\n",
		dpkgKernels: "ii \tlinux-image-6.8.0-38-generic\t600000\n" +
			"ii \tlinux-image-6.8.0-41-generic\t600000\n" +
			"ii \tlinux-image-6.8.0-45-generic\t600000\n",
	} {
		h.fake.Results[cmd] = system.Result{Stdout: out}
	}
	return h
}

// openDisk starts the TUI on h and focuses the loaded Disk screen.
func openDisk(t *testing.T, h *testHost) *teatest.TestModel {
	t.Helper()
	tm := start(h)
	waitFor(t, tm, "RAM")
	tm.Type(menuTo("Disk"))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "Cleanup")
	return tm
}

// Usage per filesystem, and every cleanup with what it would reclaim; the
// kernel cleanup names what it removes and never the running kernel.
func TestDiskShowsUsageAndCleanups(t *testing.T) {
	tm := openDisk(t, diskHost(t))
	v := ctrlCView(t, tm)
	wantAll(t, v, "/boot/efi", "41.0 GB / 50.0 GB", "82%",
		"Vacuum journal to 200 MB", "1.4 GB",
		"Clean apt cache", "8 B",
		"Remove old kernels", "614.4 MB", "6.8.0-38-generic", "[ Run ]")
	if strings.Contains(v, "6.8.0-45-generic") || strings.Contains(v, "6.8.0-41-generic") {
		t.Errorf("kept kernels offered for removal:\n%s", v)
	}
}

// With Docker, dangling images are a cleanup sized from their images; it
// prunes dangling images only. Without Docker the row is not there.
func TestDiskPrunesDanglingDockerImages(t *testing.T) {
	v := ctrlCView(t, openDisk(t, diskHost(t)))
	if strings.Contains(v, "Docker") {
		t.Errorf("Docker cleanup without Docker:\n%s", v)
	}

	h := diskHost(t)
	h.fake.Results["docker version --format {{.Server.Version}}"] = system.Result{Stdout: "28.1.1\n"}
	h.fake.Results["docker images -qf dangling=true"] = system.Result{Stdout: "aa11\nbb22\n"}
	h.fake.Results["docker image inspect --format {{.Size}} aa11 bb22"] = system.Result{Stdout: "1000000000\n2400000000\n"}
	h.fake.Results["docker image prune -f"] = system.Result{Stdout: "Deleted Images:\ndeleted: sha256:aa11\nTotal reclaimed space: 3.4GB\n"}
	tm := openDisk(t, h)
	tm.Type("4")
	waitFor(t, tm, "Prune dangling Docker images?")
	tm.Type("y")
	waitFor(t, tm, "SUMMARY")
	wantAll(t, ctrlCView(t, tm), "reclaimed up to 3.4 GB")
	if log := actionLog(t, h); !strings.Contains(log, "disk Prune dangling Docker images: ok") {
		t.Errorf("Task History:\n%s", log)
	}
	wantAll(t, oneOutput(t, h), "$ docker image prune -f", "Total reclaimed space: 3.4GB")
	for _, c := range h.fake.Calls { // dangling images only: no -a, no containers, volumes or system prune
		if strings.Contains(c, "prune") && c != "docker image prune -f" {
			t.Errorf("ran %q", c)
		}
	}
}

// A running scan can be cancelled: du is stopped and the screen says so.
func TestDiskScanCancel(t *testing.T) {
	h := diskHost(t)
	du, w := io.Pipe()
	h.fake.Streams = map[string]io.ReadCloser{"du -x -B1 -d 3 /": du}
	tm := openDisk(t, h)
	tm.Type("s")
	waitFor(t, tm, "scanning")
	io.WriteString(w, "18200000000\t/var/lib/docker\n")
	tm.Type("c")
	waitFor(t, tm, "cancelled")
	if _, err := io.WriteString(w, "1\t/x\n"); err == nil {
		t.Error("du still running after cancel")
	}
	wantAll(t, ctrlCView(t, tm), "Largest under / (depth 3) · scan cancelled")
}

// Leaving Disk through the sidebar, or quitting, stops a running scan.
func TestDiskScanStopsOnSidebarAndQuit(t *testing.T) {
	for _, leave := range []string{"sidebar", "quit"} {
		t.Run(leave, func(t *testing.T) {
			h := diskHost(t)
			du, w := io.Pipe()
			h.fake.Streams = map[string]io.ReadCloser{"du -x -B1 -d 3 /": du}
			tm := openDisk(t, h)
			tm.Type("s")
			waitFor(t, tm, "scanning")
			if leave == "sidebar" {
				tm.Send(tea.KeyPressMsg{Code: tea.KeyTab})
				tm.Type(strings.Repeat("k", slices.Index(items(), "Disk")-slices.Index(items(), "Overview")))
				tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
				waitFor(t, tm, "Uptime")
				if !pipeClosed(w) {
					t.Error("du still running after leaving through the sidebar")
				}
			}
			ctrlCView(t, tm)
			if !pipeClosed(w) {
				t.Error("du still running")
			}
		})
	}
}

// A finished scan lists the largest directories, biggest first.
func TestDiskScanListsLargest(t *testing.T) {
	h := diskHost(t)
	h.fake.Streams = map[string]io.ReadCloser{"du -x -B1 -d 3 /": io.NopCloser(strings.NewReader(
		"9100000000\t/var/log/journal\n18200000000\t/var/lib/docker\n41000000000\t/\n"))}
	tm := openDisk(t, h)
	tm.Type("s")
	waitFor(t, tm, "/var/log/journal")
	v := ctrlCView(t, tm)
	if i, j := strings.Index(v, "/var/lib/docker"), strings.Index(v, "/var/log/journal"); i < 0 || i > j {
		t.Errorf("not biggest first:\n%s", v)
	}
	wantAll(t, v, "Largest under / (depth 3)", "18.2 GB")
}

// A cleanup asks, then runs as a Task recorded in Task History.
func TestDiskCleanupRunsAsTask(t *testing.T) {
	h := diskHost(t)
	h.fake.Results["journalctl --vacuum-size=200M"] = system.Result{Stdout: "Vacuuming done, freed 1.3G\n"}
	tm := openDisk(t, h)
	tm.Type("1")
	waitFor(t, tm, "Vacuum journal to 200 MB?")
	tm.Type("y")
	waitFor(t, tm, "SUMMARY")
	v := ctrlCView(t, tm)
	wantAll(t, v, "Task: Vacuum journal to 200 MB", "Done in")
	if log := actionLog(t, h); !strings.Contains(log, "disk Vacuum journal to 200 MB: ok") {
		t.Errorf("Task History:\n%s", log)
	}
	wantAll(t, oneOutput(t, h), "$ journalctl --vacuum-size=200M", "Vacuuming done")
}

// Removing old kernels wants the dangerous confirm: nothing runs until the
// word is typed.
func TestDiskOldKernelsDangerousConfirm(t *testing.T) {
	h := diskHost(t)
	purge := "env DEBIAN_FRONTEND=noninteractive apt-get purge -y linux-image-6.8.0-38-generic"
	h.fake.Results[purge] = system.Result{}
	tm := openDisk(t, h)
	tm.Type("3")
	waitFor(t, tm, `Type "kernels" to confirm`)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // not typed yet: nothing happens
	tm.Type("kernels")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "SUMMARY")
	ctrlCView(t, tm)
	n := 0
	for _, c := range h.fake.Calls {
		if strings.Contains(c, "purge") {
			n++
		}
	}
	if n != 1 || !strings.Contains(actionLog(t, h), "disk Remove old kernels: ok") {
		t.Errorf("purges %d, Task History:\n%s", n, actionLog(t, h))
	}
}
