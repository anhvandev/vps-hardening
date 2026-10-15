package system

import (
	"fmt"
	"strings"
)

// Packages installs distro packages. Share one per process: apt-get update
// runs once, before the first apt install.
type Packages struct {
	R       Runner
	Manager string // Host.PkgManager: "apt" or "dnf"
	updated bool
}

func (p *Packages) Install(pkgs ...string) error {
	var name string
	var args []string
	switch p.Manager {
	case "apt":
		if !p.updated {
			// A failed update (e.g. one broken third-party repo) is not fatal:
			// the install below still reports any real problem.
			p.R.Run("env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "update", "-qq")
			p.updated = true
		}
		name, args = "env", []string{"DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "-qq"}
	case "dnf":
		name, args = "dnf", []string{"install", "-y"}
	default:
		return fmt.Errorf("install %s: unsupported package manager %q", strings.Join(pkgs, " "), p.Manager)
	}
	res, err := p.R.Run(name, append(args, pkgs...)...)
	if err == nil && res.Code != 0 {
		err = fmt.Errorf("exit %d: %s", res.Code, strings.TrimSpace(res.Stderr))
	}
	if err != nil {
		return fmt.Errorf("install %s: %w", strings.Join(pkgs, " "), err)
	}
	return nil
}
