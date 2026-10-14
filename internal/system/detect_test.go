package system

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetect(t *testing.T) {
	disabled := Result{Stdout: "disabled\n", Code: 1}
	inactive := Result{Stdout: "inactive\n", Code: 3}

	cases := []struct {
		fixture string
		results map[string]Result
		want    Host
	}{
		{
			fixture: "ubuntu-22.04",
			results: map[string]Result{
				"systemctl is-enabled ssh.socket": disabled,
				"systemctl is-active ssh.socket":  inactive,
			},
			want: Host{DistroID: "ubuntu", Family: "debian", Supported: true, SSHUnit: "ssh", AdminGroup: "sudo", PkgManager: "apt"},
		},
		{
			// Ubuntu 24.04 ships ssh.socket enabled but not yet started: still socket mode.
			fixture: "ubuntu-24.04",
			results: map[string]Result{
				"systemctl is-enabled ssh.socket": {Stdout: "enabled\n"},
				"systemctl is-active ssh.socket":  inactive,
			},
			want: Host{DistroID: "ubuntu", Family: "debian", Supported: true, SSHUnit: "ssh", SSHSocket: "ssh.socket", AdminGroup: "sudo", PkgManager: "apt"},
		},
		{
			fixture: "debian-12",
			results: map[string]Result{
				"systemctl is-enabled ssh.socket": disabled,
				"systemctl is-active ssh.socket":  inactive,
			},
			want: Host{DistroID: "debian", Family: "debian", Supported: true, SSHUnit: "ssh", AdminGroup: "sudo", PkgManager: "apt"},
		},
		{
			// Active but not enabled also counts as socket mode.
			fixture: "debian-13",
			results: map[string]Result{
				"systemctl is-enabled ssh.socket": disabled,
				"systemctl is-active ssh.socket":  {Stdout: "active\n"},
			},
			want: Host{DistroID: "debian", Family: "debian", Supported: true, SSHUnit: "ssh", SSHSocket: "ssh.socket", AdminGroup: "sudo", PkgManager: "apt"},
		},
		{
			fixture: "rocky-8",
			results: map[string]Result{
				"getenforce": {Stdout: "Disabled\n"},
			},
			want: Host{DistroID: "rocky", Family: "rhel", Supported: true, SSHUnit: "sshd", AdminGroup: "wheel", PkgManager: "dnf"},
		},
		{
			fixture: "rocky-9",
			results: map[string]Result{
				"systemctl is-enabled sshd.socket": disabled,
				"systemctl is-active sshd.socket":  inactive,
				"getenforce":                       {Stdout: "Enforcing\n"},
			},
			want: Host{DistroID: "rocky", Family: "rhel", Supported: true, SSHUnit: "sshd", SELinux: true, AdminGroup: "wheel", PkgManager: "dnf"},
		},
		{
			// Unsupported distro: best-effort defaults, flagged unsupported.
			fixture: "arch",
			want:    Host{DistroID: "arch", SSHUnit: "sshd", AdminGroup: "wheel"},
		},
	}

	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			got, err := Detect(&Fake{Results: c.results}, filepath.Join("testdata", c.fixture))
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if got != c.want {
				t.Fatalf("\ngot  %+v\nwant %+v", got, c.want)
			}
		})
	}
}

func TestDetectAlmaIsRhel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "os-release")
	os.WriteFile(path, []byte("ID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\n"), 0o644)
	got, err := Detect(&Fake{}, path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Family != "rhel" || !got.Supported || got.PkgManager != "dnf" {
		t.Fatalf("got %+v", got)
	}
}

func TestPreflight(t *testing.T) {
	dir := t.TempDir()
	if err := Preflight(0, dir); err != nil {
		t.Fatalf("root on systemd: %v", err)
	}
	if err := Preflight(1000, dir); err == nil {
		t.Fatal("non-root must fail")
	}
	if err := Preflight(0, filepath.Join(dir, "missing")); err == nil {
		t.Fatal("no systemd must fail")
	}
}

func TestDetectMissingOSReleaseIsError(t *testing.T) {
	if _, err := Detect(&Fake{}, filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error")
	}
}
