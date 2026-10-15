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
			want: Host{DistroID: "ubuntu", Version: "22.04", Family: "debian", Supported: true, SSHUnit: "ssh", AdminGroup: "sudo", PkgManager: "apt"},
		},
		{
			// Ubuntu 24.04 ships ssh.socket enabled but not yet started: still socket mode.
			fixture: "ubuntu-24.04",
			results: map[string]Result{
				"systemctl is-enabled ssh.socket": {Stdout: "enabled\n"},
				"systemctl is-active ssh.socket":  inactive,
			},
			want: Host{DistroID: "ubuntu", Version: "24.04", Family: "debian", Supported: true, SSHUnit: "ssh", SSHSocket: "ssh.socket", AdminGroup: "sudo", PkgManager: "apt"},
		},
		{
			fixture: "debian-12",
			results: map[string]Result{
				"systemctl is-enabled ssh.socket": disabled,
				"systemctl is-active ssh.socket":  inactive,
			},
			want: Host{DistroID: "debian", Version: "12", Family: "debian", Supported: true, SSHUnit: "ssh", AdminGroup: "sudo", PkgManager: "apt"},
		},
		{
			// Active but not enabled also counts as socket mode.
			fixture: "debian-13",
			results: map[string]Result{
				"systemctl is-enabled ssh.socket": disabled,
				"systemctl is-active ssh.socket":  {Stdout: "active\n"},
			},
			want: Host{DistroID: "debian", Version: "13", Family: "debian", Supported: true, SSHUnit: "ssh", SSHSocket: "ssh.socket", AdminGroup: "sudo", PkgManager: "apt"},
		},
		{
			fixture: "rocky-8",
			results: map[string]Result{
				"getenforce": {Stdout: "Disabled\n"},
			},
			want: Host{DistroID: "rocky", Version: "8.10", Family: "rhel", Supported: true, SSHUnit: "sshd", AdminGroup: "wheel", PkgManager: "dnf"},
		},
		{
			fixture: "rocky-9",
			results: map[string]Result{
				"systemctl is-enabled sshd.socket": disabled,
				"systemctl is-active sshd.socket":  inactive,
				"getenforce":                       {Stdout: "Enforcing\n"},
			},
			want: Host{DistroID: "rocky", Version: "9.4", Family: "rhel", Supported: true, SSHUnit: "sshd", SELinux: true, AdminGroup: "wheel", PkgManager: "dnf"},
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
	os.WriteFile(path, []byte("ID=\"almalinux\"\nVERSION_ID=\"9.4\"\nID_LIKE=\"rhel centos fedora\"\n"), 0o644)
	got, err := Detect(&Fake{}, path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Family != "rhel" || !got.Supported || got.PkgManager != "dnf" {
		t.Fatalf("got %+v", got)
	}
}

// Supported = spec list: Ubuntu 22.04/24.04, Debian 12/13, Rocky/Alma 8/9
// (major version on RHEL-likes). Anything else is best-effort.
func TestDetectSupportedChecksVersion(t *testing.T) {
	cases := map[string]bool{
		"ID=ubuntu\nVERSION_ID=\"22.04\"":  true,
		"ID=ubuntu\nVERSION_ID=\"24.04\"":  true,
		"ID=ubuntu\nVERSION_ID=\"20.04\"":  false,
		"ID=ubuntu\nVERSION_ID=\"24.10\"":  false,
		"ID=debian\nVERSION_ID=\"12\"":     true,
		"ID=debian\nVERSION_ID=\"13\"":     true,
		"ID=debian\nVERSION_ID=\"11\"":     false,
		"ID=debian":                        false, // testing/sid: no VERSION_ID
		"ID=rocky\nVERSION_ID=\"8.10\"":    true,
		"ID=rocky\nVERSION_ID=\"9.4\"":     true,
		"ID=rocky\nVERSION_ID=\"10.0\"":    false,
		"ID=almalinux\nVERSION_ID=\"9.4\"": true,
		"ID=almalinux\nVERSION_ID=\"7.9\"": false,
		"ID=arch\nVERSION_ID=\"20240101\"": false,
		"ID=rocky\nVERSION_ID=\"89\"":      false,
	}
	for osr, want := range cases {
		path := filepath.Join(t.TempDir(), "os-release")
		os.WriteFile(path, []byte(osr+"\n"), 0o644)
		got, err := Detect(&Fake{}, path)
		if err != nil {
			t.Fatal(err)
		}
		if got.Supported != want {
			t.Errorf("%q: Supported = %v, want %v", osr, got.Supported, want)
		}
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

// Right after boot systemctl can't reach PID 1 yet; every unit then looks
// disabled, so socket mode would be silently missed. Detect must refuse.
func TestDetectSystemdUnreachableIsError(t *testing.T) {
	bus := Result{Stderr: "Failed to connect to bus: No such file or directory\n", Code: 1}
	f := &Fake{Results: map[string]Result{
		"systemctl is-system-running":     bus,
		"systemctl is-enabled ssh.socket": bus,
		"systemctl is-active ssh.socket":  bus,
	}}
	if _, err := Detect(f, filepath.Join("testdata", "ubuntu-24.04")); err == nil {
		t.Fatal("expected error when systemd is unreachable")
	}
}
