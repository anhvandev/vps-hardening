package disk_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/anhvandev/vpsctl/internal/disk"
	"github.com/anhvandev/vpsctl/internal/system"
)

func TestJournalReclaimsAboveTheLimit(t *testing.T) {
	r := &system.Fake{Results: map[string]system.Result{
		"journalctl --disk-usage":       {Stdout: "Archived and active journals take up 1.5G in the file system.\n"},
		"journalctl --vacuum-size=200M": {},
	}}
	c := disk.Journal(r, 200)
	if c.Name != "Vacuum journal to 200 MB" || c.Reclaimable != 1610612736-209715200 || c.Why != "" || c.Dangerous {
		t.Errorf("got %+v", c)
	}
	if err := c.Run(r); err != nil {
		t.Fatal(err)
	}
	if r.Calls[len(r.Calls)-1] != "journalctl --vacuum-size=200M" {
		t.Errorf("ran %q", r.Calls)
	}

	r.Results["journalctl --disk-usage"] = system.Result{Stdout: "Archived and active journals take up 120.0M in the file system.\n"}
	if c := disk.Journal(r, 200); c.Reclaimable != 0 {
		t.Errorf("under the limit reclaims %d", c.Reclaimable)
	}
	if c := disk.Journal(&system.Fake{}, 200); c.Why == "" {
		t.Error("no journalctl, yet runnable")
	}
}

func TestPackageCache(t *testing.T) {
	root := t.TempDir()
	for p, s := range map[string]string{
		"/var/cache/apt/archives/a.deb":         "12345",
		"/var/cache/apt/archives/partial/b.deb": "678",
		"/var/cache/apt/pkgcache.bin":           "not the archives",
	} {
		os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755)
		os.WriteFile(filepath.Join(root, p), []byte(s), 0o644)
	}
	r := &system.Fake{Results: map[string]system.Result{"apt-get clean": {}, "dnf clean all": {}}}
	c := disk.PackageCache(r, root, "apt")
	if c.Name != "Clean apt cache" || c.Reclaimable != 8 || c.Why != "" {
		t.Errorf("got %+v", c)
	}
	c.Run(r)

	os.MkdirAll(filepath.Join(root, "/var/cache/dnf/baseos"), 0o755)
	os.WriteFile(filepath.Join(root, "/var/cache/dnf/baseos/repomd.xml"), []byte("1234"), 0o644)
	c = disk.PackageCache(r, root, "dnf")
	if c.Name != "Clean dnf cache" || c.Reclaimable != 4 {
		t.Errorf("got %+v", c)
	}
	c.Run(r)
	if !slices.Equal(r.Calls, []string{"apt-get clean", "dnf clean all"}) {
		t.Errorf("ran %q", r.Calls)
	}
}

const dpkgKernels = `dpkg-query -W -f=${db:Status-Abbrev}\t${Package}\t${Installed-Size}\n linux-*`

// Kept: the running kernel, any newer one (installed, pending reboot) and
// the newest older one. Versions compare numerically (-9 < -38 < -100).
func TestOldKernelsApt(t *testing.T) {
	r := &system.Fake{Results: map[string]system.Result{
		"uname -r": {Stdout: "6.8.0-45-generic\n"},
		dpkgKernels: {Stdout: "ii \tlinux-image-6.8.0-9-generic\t10000\n" +
			"ii \tlinux-modules-6.8.0-9-generic\t20000\n" +
			"ii \tlinux-image-6.8.0-38-generic\t10000\n" +
			"ii \tlinux-modules-6.8.0-38-generic\t20000\n" +
			"ii \tlinux-modules-extra-6.8.0-38-generic\t30000\n" +
			"ii \tlinux-headers-6.8.0-38-generic\t1000\n" +
			"ii \tlinux-image-6.8.0-41-generic\t10000\n" +
			"ii \tlinux-image-unsigned-6.8.0-45-generic\t10000\n" +
			"ii \tlinux-image-6.8.0-45-generic\t10000\n" +
			"ii \tlinux-image-6.8.0-100-generic\t10000\n" +
			"ii \tlinux-image-generic\t20\n" +
			"ii \tlinux-base\t50\n" +
			"rc \tlinux-image-6.8.0-5-generic\t10000\n" +
			"ii \tlinux-firmware\t500000\n"},
	}}
	c := disk.OldKernels(r, "apt")
	if c.Name != "Remove old kernels" || c.Detail != "6.8.0-9-generic, 6.8.0-38-generic" ||
		c.Reclaimable != 91000*1024 || !c.Dangerous || c.Why != "" {
		t.Fatalf("got %+v", c)
	}
	purge := "env DEBIAN_FRONTEND=noninteractive apt-get purge -y linux-image-6.8.0-9-generic linux-modules-6.8.0-9-generic " +
		"linux-image-6.8.0-38-generic linux-modules-6.8.0-38-generic linux-modules-extra-6.8.0-38-generic linux-headers-6.8.0-38-generic"
	r.Results[purge] = system.Result{}
	if err := c.Run(r); err != nil {
		t.Fatal(err)
	}
	if r.Calls[len(r.Calls)-1] != purge {
		t.Errorf("ran %q", r.Calls)
	}
}

// Booted into a kernel picked for removal since the list was read: refused.
func TestOldKernelsNeverRemovesTheRunningOne(t *testing.T) {
	r := &system.Fake{Results: map[string]system.Result{
		"uname -r": {Stdout: "6.8.0-45-generic\n"},
		dpkgKernels: {Stdout: "ii \tlinux-image-6.8.0-38-generic\t10000\n" +
			"ii \tlinux-image-6.8.0-41-generic\t10000\n" +
			"ii \tlinux-image-6.8.0-45-generic\t10000\n"},
	}}
	c := disk.OldKernels(r, "apt")
	if c.Detail != "6.8.0-38-generic" {
		t.Fatalf("got %+v", c)
	}
	r.Results["uname -r"] = system.Result{Stdout: "6.8.0-38-generic\n"}
	if err := c.Run(r); err == nil {
		t.Error("removed the running kernel")
	}
	for _, call := range r.Calls {
		if call != "uname -r" && call != dpkgKernels {
			t.Errorf("ran %q", call)
		}
	}

	if c := disk.OldKernels(&system.Fake{Results: map[string]system.Result{dpkgKernels: {}}}, "apt"); c.Why == "" {
		t.Error("running kernel unknown, yet runnable")
	}
}

func TestOldKernelsDnf(t *testing.T) {
	rpm := `rpm -qa --qf %{NAME}\t%{VERSION}-%{RELEASE}.%{ARCH}\t%{SIZE}\n kernel*`
	r := &system.Fake{Results: map[string]system.Result{
		"uname -r": {Stdout: "5.14.0-503.14.1.el9_5.x86_64\n"},
		rpm: {Stdout: "kernel-core\t5.14.0-362.8.1.el9_3.x86_64\t1000\n" +
			"kernel-modules\t5.14.0-362.8.1.el9_3.x86_64\t2000\n" +
			"kernel\t5.14.0-362.8.1.el9_3.x86_64\t0\n" +
			"kernel-core\t5.14.0-427.13.1.el9_4.x86_64\t1000\n" +
			"kernel-core\t5.14.0-503.14.1.el9_5.x86_64\t1000\n" +
			"kernel-headers\t5.14.0-362.8.1.el9_3.x86_64\t5000\n" +
			"kernel-tools\t5.14.0-503.14.1.el9_5.x86_64\t300\n"},
		"dnf remove -y kernel-core-5.14.0-362.8.1.el9_3.x86_64 kernel-modules-5.14.0-362.8.1.el9_3.x86_64 kernel-5.14.0-362.8.1.el9_3.x86_64": {},
	}}
	c := disk.OldKernels(r, "dnf")
	if c.Detail != "5.14.0-362.8.1.el9_3.x86_64" || c.Reclaimable != 3000 {
		t.Fatalf("got %+v", c)
	}
	if err := c.Run(r); err != nil {
		t.Fatal(err)
	}
}
