package system

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
)

// Host is what vpsctl needs to know about the machine it runs on.
type Host struct {
	DistroID   string // os-release ID, e.g. "ubuntu", "rocky"
	Version    string // os-release VERSION_ID, e.g. "24.04", "9.4"
	Family     string // "debian", "rhel", or "" when unknown (best-effort)
	Supported  bool   // false → caller should warn and proceed best-effort
	SSHUnit    string // "ssh" (debian family) or "sshd"
	SSHSocket  string // socket unit ("ssh.socket"/"sshd.socket") when SSH is socket-activated, else ""
	SELinux    bool   // SELinux present and not Disabled
	AdminGroup string // "sudo" (debian family) or "wheel"
	PkgManager string // "apt", "dnf", or "" when unknown
}

// supported maps os-release ID to supported VERSION_IDs (major only on RHEL-likes).
var supported = map[string][]string{
	"ubuntu":    {"22.04", "24.04"},
	"debian":    {"12", "13"},
	"rocky":     {"8", "9"},
	"almalinux": {"8", "9"},
}

// Detect reads osReleasePath (normally /etc/os-release) and probes the host via r.
func Detect(r Runner, osReleasePath string) (Host, error) {
	data, err := os.ReadFile(osReleasePath)
	if err != nil {
		return Host{}, err
	}
	osr := parseOSRelease(string(data))

	h := Host{DistroID: osr["ID"], Version: osr["VERSION_ID"]}
	version := h.Version
	if osr["ID"] == "rocky" || osr["ID"] == "almalinux" {
		version, _, _ = strings.Cut(version, ".")
	}
	h.Supported = slices.Contains(supported[osr["ID"]], version)
	for _, id := range append([]string{osr["ID"]}, strings.Fields(osr["ID_LIKE"])...) {
		if h.Family != "" {
			break
		}
		switch id {
		case "debian", "ubuntu":
			h.Family = "debian"
		case "rhel", "fedora", "centos":
			h.Family = "rhel"
		}
	}

	h.SSHUnit, h.AdminGroup = "sshd", "wheel"
	switch h.Family {
	case "debian":
		h.SSHUnit, h.AdminGroup, h.PkgManager = "ssh", "sudo", "apt"
	case "rhel":
		h.PkgManager = "dnf"
	}

	// While PID 1 is still booting, systemctl can't reach it and prints its
	// state only to stderr; every unit would then look disabled.
	if res, err := r.Run("systemctl", "is-system-running"); err == nil && strings.TrimSpace(res.Stdout) == "" {
		return Host{}, fmt.Errorf("systemd not reachable (still booting?), retry in a few seconds: %s", strings.TrimSpace(res.Stderr))
	}

	// Socket activation: enabled-but-inactive counts too (Ubuntu 24.04+).
	for _, unit := range []string{"ssh.socket", "sshd.socket"} {
		if ok(r, "systemctl", "is-enabled", unit) || ok(r, "systemctl", "is-active", unit) {
			h.SSHSocket = unit
			break
		}
	}

	if res, err := r.Run("getenforce"); err == nil && res.Code == 0 {
		h.SELinux = strings.TrimSpace(res.Stdout) != "Disabled"
	}
	return h, nil
}

// Preflight fails unless running as root (euid 0) on a systemd host, i.e.
// systemdRunDir (normally /run/systemd/system) exists.
func Preflight(euid int, systemdRunDir string) error {
	if euid != 0 {
		return errors.New("must run as root")
	}
	if fi, err := os.Stat(systemdRunDir); err != nil || !fi.IsDir() {
		return errors.New("unsupported environment: systemd required (PID 1)")
	}
	return nil
}

func ok(r Runner, name string, args ...string) bool {
	res, err := r.Run(name, args...)
	return err == nil && res.Code == 0
}

func parseOSRelease(s string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		k, v, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found || strings.HasPrefix(k, "#") {
			continue
		}
		if u, err := strconv.Unquote(v); err == nil {
			v = u
		} else {
			v = strings.Trim(v, `'"`)
		}
		m[k] = v
	}
	return m
}
