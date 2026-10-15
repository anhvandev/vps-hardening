package updates

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/anhvandev/vpsctl/internal/system"
)

const aptSim = "Reading package lists...\nBuilding dependency tree...\n" +
	"The following packages will be upgraded:\n  libnss-systemd perl-base curl\n" +
	"Inst libnss-systemd [255.4-1ubuntu8.17] (255.4-1ubuntu8.18 Ubuntu:24.04/noble-security [amd64]) []\n" +
	"Inst perl-base [5.36.0-7+deb12u3] (5.36.0-7+deb12u4 Debian-Security:12/oldstable-security [amd64])\n" +
	"Inst curl [8.5.0-2ubuntu10.5] (8.5.0-2ubuntu10.6 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])\n" +
	"Inst libfoo2 (2.0-1 Ubuntu:24.04/noble-updates [amd64])\n" +
	"Inst tzdata [2024a-3ubuntu1.1] (2025b-0ubuntu0.24.04 Ubuntu:24.04/noble-updates [all])\n" +
	"Conf libnss-systemd (255.4-1ubuntu8.18 Ubuntu:24.04/noble-security [amd64])\n"

const aptSimCmd = "apt-get -s -o Debug::NoLocking=true upgrade"

func TestAptList(t *testing.T) {
	f := &system.Fake{Results: map[string]system.Result{aptSimCmd: {Stdout: aptSim}}}
	got, err := List(f, "apt")
	if err != nil {
		t.Fatal(err)
	}
	want := []Package{
		{"libnss-systemd", "255.4-1ubuntu8.17", "255.4-1ubuntu8.18", true},
		{"perl-base", "5.36.0-7+deb12u3", "5.36.0-7+deb12u4", true},
		{"curl", "8.5.0-2ubuntu10.5", "8.5.0-2ubuntu10.6", true}, // one of several origins is -security
		{"libfoo2", "", "2.0-1", false},                          // a new dependency
		{"tzdata", "2024a-3ubuntu1.1", "2025b-0ubuntu0.24.04", false},
	}
	if !slices.Equal(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

// dnfHost scripts check-update (one name wrapped onto two lines, an
// obsoletes section after), rpm's installed versions and the security
// advisories (one package under two advisories, one at an older version).
func dnfHost() *system.Fake {
	return &system.Fake{Results: map[string]system.Result{
		"dnf -q check-update": {Code: 100, Stdout: "\n" +
			"acl.x86_64                             2.4.0-1.el8_10                     baseos\n" +
			"openssl-libs.x86_64                    1:3.5.8-3.el9_8                    baseos\n" +
			"python3-a-very-long-package-name.noarch\n" +
			"                                       1.2-3.el9                          appstream\n" +
			"Obsoleting Packages\n" +
			"grub2-tools.x86_64                     1:2.06-94.el9                      baseos\n" +
			"    grub2-tools.x86_64                 1:2.06-90.el9                      @baseos\n"},
		"rpm -q --qf %{NAME}.%{ARCH} %{EPOCH}:%{VERSION}-%{RELEASE}\n acl.x86_64 openssl-libs.x86_64 python3-a-very-long-package-name.noarch": {
			Stdout: "acl.x86_64 (none):2.3.1-4.el8\nopenssl-libs.x86_64 1:3.5.8-2.el9_8\npython3-a-very-long-package-name.noarch (none):1.2-2.el9\n"},
		"dnf -q updateinfo list --security": {Stdout: "" +
			"RLSA-2025:1111 Important/Sec. openssl-libs-1:3.5.8-3.el9_8.x86_64\n" +
			"RLSA-2025:0999 Moderate/Sec.  openssl-libs-1:3.5.8-1.el9_8.x86_64\n" +
			"RLSA-2025:2222 Low/Sec.       acl-2.4.0-1.el8_10.x86_64\n"},
	}}
}

func TestDnfList(t *testing.T) {
	got, err := List(dnfHost(), "dnf")
	if err != nil {
		t.Fatal(err)
	}
	want := []Package{
		{"acl", "2.3.1-4.el8", "2.4.0-1.el8_10", true},
		{"openssl-libs", "1:3.5.8-2.el9_8", "1:3.5.8-3.el9_8", true},
		{"python3-a-very-long-package-name", "1.2-2.el9", "1.2-3.el9", false},
	}
	if !slices.Equal(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

// Nothing pending: check-update exits 0 and nothing else runs.
func TestDnfListNone(t *testing.T) {
	f := &system.Fake{Results: map[string]system.Result{"dnf -q check-update": {Stdout: "\n"}}}
	if got, err := List(f, "dnf"); err != nil || len(got) != 0 {
		t.Errorf("got %v, %v", got, err)
	}
}

func TestDnfListError(t *testing.T) {
	f := &system.Fake{Results: map[string]system.Result{"dnf -q check-update": {Code: 1, Stderr: "Error: Failed to download metadata"}}}
	if _, err := List(f, "dnf"); err == nil {
		t.Error("want an error")
	}
}

// Installing security updates installs exactly the security packages (apt)
// or lets dnf pick them by advisory; installing all upgrades everything.
func TestInstall(t *testing.T) {
	aptSec := "env DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=--force-confold --only-upgrade libnss-systemd perl-base curl"
	aptAll := "env DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -o Dpkg::Options::=--force-confold"
	for _, c := range []struct {
		manager  string
		security bool
		want     []string
	}{
		{"apt", true, []string{aptSimCmd, aptSec}},
		{"apt", false, []string{aptAll}},
		{"dnf", true, []string{"dnf -y upgrade --security"}},
		{"dnf", false, []string{"dnf -y upgrade"}},
	} {
		f := &system.Fake{Results: map[string]system.Result{aptSimCmd: {Stdout: aptSim}, aptSec: {}, aptAll: {},
			"dnf -y upgrade --security": {}, "dnf -y upgrade": {}}}
		if err := Install(f, c.manager, c.security); err != nil {
			t.Errorf("%s security=%v: %v", c.manager, c.security, err)
		}
		if !slices.Equal(f.Calls, c.want) {
			t.Errorf("%s security=%v ran %q, want %q", c.manager, c.security, f.Calls, c.want)
		}
	}
}

// No security update pending on apt: nothing is installed.
func TestAptInstallSecurityNone(t *testing.T) {
	f := &system.Fake{Results: map[string]system.Result{aptSimCmd: {Stdout: "Inst tzdata [1] (2 Ubuntu:24.04/noble-updates [all])\n"}}}
	if err := Install(f, "apt", true); err != nil || len(f.Calls) != 1 {
		t.Errorf("ran %q, %v", f.Calls, err)
	}
}

func TestInstallFailure(t *testing.T) {
	f := &system.Fake{Results: map[string]system.Result{"dnf -y upgrade": {Code: 1, Stderr: "Error: no space left"}}}
	if err := Install(f, "dnf", false); err == nil || !strings.Contains(err.Error(), "no space left") {
		t.Errorf("got %v", err)
	}
}

// apt: Ubuntu's reboot-required flag file, naming the kernel from its .pkgs
// list; dnf: needs-restarting's exit code, unknown when it is missing.
func TestRebootNeeded(t *testing.T) {
	root := t.TempDir()
	f := &system.Fake{}
	if needed, known, _ := RebootNeeded(f, root, "apt"); needed || !known {
		t.Errorf("apt without the flag: needed=%v known=%v", needed, known)
	}
	os.MkdirAll(filepath.Join(root, "/var/run"), 0o755)
	os.WriteFile(filepath.Join(root, "/var/run/reboot-required"), []byte("*** System restart required ***\n"), 0o644)
	if needed, known, kernel := RebootNeeded(f, root, "apt"); !needed || !known || kernel != "" {
		t.Errorf("apt flag: needed=%v known=%v kernel=%q", needed, known, kernel)
	}
	os.WriteFile(filepath.Join(root, "/var/run/reboot-required.pkgs"), []byte("libc6\nlinux-image-6.8.0-49-generic\nlinux-base\n"), 0o644)
	if _, _, kernel := RebootNeeded(f, root, "apt"); kernel != "6.8.0-49-generic" {
		t.Errorf("kernel %q", kernel)
	}

	if _, known, _ := RebootNeeded(f, root, "dnf"); known {
		t.Error("dnf without needs-restarting is known")
	}
	f.Results = map[string]system.Result{"needs-restarting -r": {Code: 1}}
	if needed, known, _ := RebootNeeded(f, root, "dnf"); !needed || !known {
		t.Errorf("dnf rc 1: needed=%v known=%v", needed, known)
	}
	f.Results["needs-restarting -r"] = system.Result{}
	if needed, known, _ := RebootNeeded(f, root, "dnf"); needed || !known {
		t.Errorf("dnf rc 0: needed=%v known=%v", needed, known)
	}
}

func TestRefresh(t *testing.T) {
	for manager, cmd := range map[string]string{
		"apt": "env DEBIAN_FRONTEND=noninteractive apt-get update",
		"dnf": "dnf makecache",
	} {
		f := &system.Fake{Results: map[string]system.Result{cmd: {}}}
		if err := Refresh(f, manager); err != nil || !slices.Equal(f.Calls, []string{cmd}) {
			t.Errorf("%s: ran %q, %v", manager, f.Calls, err)
		}
		f.Results[cmd] = system.Result{Code: 100, Stderr: "E: Failed to fetch"}
		if err := Refresh(f, manager); err == nil {
			t.Errorf("%s: failed refresh not reported", manager)
		}
	}
}
