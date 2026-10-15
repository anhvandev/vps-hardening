// Package updates lists pending package updates (security or other) and
// installs them through apt or dnf.
package updates

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/anhvandev/vpsctl/internal/system"
)

// Package is one pending update.
type Package struct {
	Name     string // apt: "openssl"; dnf: "openssl.x86_64"
	Current  string // installed version, "" for a new dependency or unknown
	New      string
	Security bool
}

// List reads the pending updates from the package lists as they are (see
// Refresh). manager is Host.PkgManager.
func List(r system.Runner, manager string) ([]Package, error) {
	switch manager {
	case "apt":
		return aptList(r)
	case "dnf":
		return dnfList(r)
	}
	return nil, fmt.Errorf("unsupported package manager %q", manager)
}

// Refresh downloads the package lists, so List and Install see what the
// repositories offer now.
func Refresh(r system.Runner, manager string) error {
	if manager == "dnf" {
		_, err := run(r, "dnf", "makecache")
		return err
	}
	_, err := run(r, "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "update")
	return err
}

// Install installs the pending security updates, or all of them, from the
// package lists as they are (see Refresh). Config files changed by hand are
// kept.
func Install(r system.Runner, manager string, security bool) error {
	apt := []string{"DEBIAN_FRONTEND=noninteractive", "apt-get"}
	keep := []string{"-y", "-o", "Dpkg::Options::=--force-confold"}
	var err error
	switch {
	case manager == "dnf" && security:
		_, err = run(r, "dnf", "-y", "upgrade", "--security")
	case manager == "dnf":
		_, err = run(r, "dnf", "-y", "upgrade")
	case security:
		ps, lerr := aptList(r)
		if lerr != nil {
			return lerr
		}
		args := append(append(append(apt, "install"), keep...), "--only-upgrade")
		n := len(args)
		for _, p := range ps { // a new package (a kernel) comes in with the one it is pulled by
			if p.Security && p.Current != "" {
				args = append(args, p.Name)
			}
		}
		if len(args) > n {
			_, err = run(r, "env", args...)
		}
	default:
		_, err = run(r, "env", append(append(apt, "--with-new-pkgs", "upgrade"), keep...)...)
	}
	return err
}

// RebootNeeded reports whether installed updates wait for a reboot (known
// false when the machine can't tell) and the new kernel's release, if that
// is known to be one of them. Files are read under root.
// ponytail: apt relies on Ubuntu's flag file, which Debian usually lacks; compare
// uname -r with the newest linux-image if Debian needs it.
func RebootNeeded(r system.Runner, root, manager string) (needed, known bool, kernel string) {
	if manager == "dnf" {
		res, err := r.Run("needs-restarting", "-r")
		return err == nil && res.Code == 1, err == nil && (res.Code == 0 || res.Code == 1), ""
	}
	if _, err := os.Stat(filepath.Join(root, "/var/run/reboot-required")); err != nil {
		return false, true, ""
	}
	b, _ := os.ReadFile(filepath.Join(root, "/var/run/reboot-required.pkgs"))
	for _, p := range strings.Fields(string(b)) {
		if k, ok := strings.CutPrefix(p, "linux-image-"); ok {
			kernel = k
		}
	}
	return true, true, kernel
}

// aptInst is a simulated upgrade's "Inst name [cur] (new origins [arch])".
var aptInst = regexp.MustCompile(`^Inst (\S+) (?:\[(\S+)\] )?\((\S+) (.+) \[(\S+)\]\)`)

// aptList is what `apt-get --with-new-pkgs upgrade` would install: new
// packages too (a new kernel is not kept back), never a removal. Security
// means an origin in a -security suite (noble-security, bookworm-security, …).
func aptList(r system.Runner) ([]Package, error) {
	out, err := run(r, "apt-get", "-s", "--with-new-pkgs", "-o", "Debug::NoLocking=true", "upgrade")
	if err != nil {
		return nil, err
	}
	var ps []Package
	for _, line := range strings.Split(out, "\n") {
		m := aptInst.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		p := Package{Name: m[1], Current: m[2], New: m[3]}
		for _, o := range strings.Split(m[4], ", ") {
			_, suite, _ := strings.Cut(o, "/")
			p.Security = p.Security || strings.HasSuffix(suite, "-security")
		}
		ps = append(ps, p)
	}
	return ps, nil
}

// dnfList is what `dnf upgrade` would install, with the installed versions
// from rpm; security means named by a security advisory.
func dnfList(r system.Runner) ([]Package, error) {
	res, err := r.Run("dnf", "-q", "check-update")
	if err == nil && res.Code != 0 && res.Code != 100 { // 100: updates pending
		err = fmt.Errorf("exit %d: %s", res.Code, strings.TrimSpace(res.Stderr))
	}
	if err != nil {
		return nil, fmt.Errorf("dnf check-update: %w", err)
	}
	pending, _, _ := strings.Cut(res.Stdout, "Obsoleting Packages")
	f := strings.Fields(pending) // name.arch version repo, a long name may wrap its line
	var keys []string
	newer := map[string]string{}
	for i := 0; i+2 < len(f); i += 3 {
		keys = append(keys, f[i])
		newer[f[i]] = f[i+1]
	}
	if len(keys) == 0 {
		return nil, nil
	}
	cur := map[string]string{}
	if out, err := run(r, "rpm", append([]string{"-q", "--qf", "%{NAME}.%{ARCH} %{EPOCH}:%{VERSION}-%{RELEASE}\n"}, keys...)...); err == nil {
		for _, line := range strings.Split(out, "\n") {
			if k, v, ok := strings.Cut(line, " "); ok {
				cur[k] = strings.TrimPrefix(v, "(none):")
			}
		}
	}
	sec := map[string]bool{}
	out, err := run(r, "dnf", "-q", "updateinfo", "list", "--security")
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) == 3 && strings.HasSuffix(f[1], "/Sec.") {
			sec[nevraKey(f[2])] = true
		}
	}
	var ps []Package
	for _, k := range keys {
		name, _ := cutLast(k, ".")
		ps = append(ps, Package{name, cur[k], newer[k], sec[k]})
	}
	return ps, nil
}

// nevraKey is "name.arch" of "name-[epoch:]version-release.arch".
func nevraKey(nevra string) string {
	rest, arch := cutLast(nevra, ".")
	name, _ := cutLast(rest, "-") // drop release
	name, _ = cutLast(name, "-")  // drop [epoch:]version
	return name + "." + arch
}

// cutLast splits s around its last sep.
func cutLast(s, sep string) (before, after string) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):]
	}
	return s, ""
}

// run runs a command that must exit 0 and returns its stdout.
func run(r system.Runner, name string, args ...string) (string, error) {
	res, err := r.Run(name, args...)
	if err == nil && res.Code != 0 {
		err = fmt.Errorf("exit %d: %s", res.Code, strings.TrimSpace(res.Stderr))
	}
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return res.Stdout, nil
}
