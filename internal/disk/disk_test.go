package disk_test

import (
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/anhvandev/vpsctl/internal/disk"
	"github.com/anhvandev/vpsctl/internal/system"
)

const dfCmd = "df -B1 --output=source,fstype,size,used,avail,target -x tmpfs -x devtmpfs -x overlay -x squashfs -x efivarfs"

func TestFilesystems(t *testing.T) {
	r := &system.Fake{Results: map[string]system.Result{dfCmd: {Stdout: "Filesystem     Type  1B-blocks  Used  Avail Mounted on\n" +
		"/dev/vda1      ext4  50000000000 41000000000 9000000000 /\n" +
		"/dev/vda15     vfat  1000000000 200000000 800000000 /boot/efi\n" +
		"/dev/vdb1      xfs   2000 1000 1000 /mnt/my data\n"}}}
	got, err := disk.Filesystems(r)
	if err != nil {
		t.Fatal(err)
	}
	want := []disk.Filesystem{
		{Mount: "/", Type: "ext4", Size: 50000000000, Used: 41000000000},
		{Mount: "/boot/efi", Type: "vfat", Size: 1000000000, Used: 200000000},
		{Mount: "/mnt/my data", Type: "xfs", Size: 2000, Used: 1000},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v", got)
	}
}

// The scan streams du over one filesystem; Largest keeps the biggest
// directories, biggest first, without the mount itself.
func TestLargestDirectories(t *testing.T) {
	r := &system.Fake{Streams: map[string]io.ReadCloser{"du -x -B1 -d 3 /": io.NopCloser(strings.NewReader(
		"4096\t/home/anh/empty\n" +
			"9100000000\t/var/log/journal\n" +
			"18200000000\t/var/lib/docker\n" +
			"4000000000\t/home/anh/backups\n" +
			"41000000000\t/\n"))}}
	rc, err := disk.Scan(r, "/")
	if err != nil {
		t.Fatal(err)
	}
	got, err := disk.Largest(rc, "/", 3)
	if err != nil {
		t.Fatal(err)
	}
	want := []disk.Dir{{Path: "/var/lib/docker", Size: 18200000000}, {Path: "/var/log/journal", Size: 9100000000}, {Path: "/home/anh/backups", Size: 4000000000}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v", got)
	}
}

func TestScanNeedsAStreamingRunner(t *testing.T) {
	if _, err := disk.Scan(runOnly{}, "/"); err == nil {
		t.Error("scan started without a way to stop it")
	}
}

type runOnly struct{}

func (runOnly) Run(string, ...string) (system.Result, error) { return system.Result{}, nil }
