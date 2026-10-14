// Command vpsctl hardens and manages a single VPS. Run as root on the VPS.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/anhvandev/vpsctl/internal/system"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Println("vpsctl: TUI not implemented yet; use `vpsctl harden`")
		return
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(version)
	case "harden":
		fs := flag.NewFlagSet("harden", flag.ExitOnError)
		fs.Parse(os.Args[2:])
		if err := harden(); err != nil {
			fmt.Fprintln(os.Stderr, "ERROR:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "usage: vpsctl [harden|version]\n")
		os.Exit(2)
	}
}

func harden() error {
	if err := system.Preflight(os.Geteuid(), "/run/systemd/system"); err != nil {
		return err
	}
	h, err := system.Detect(system.Exec{}, "/etc/os-release")
	if err != nil {
		return err
	}
	if !h.Supported {
		fmt.Fprintf(os.Stderr, "WARN: distro %q not in the supported set; proceeding best-effort\n", h.DistroID)
	}
	fmt.Printf("%+v\n", h)
	return fmt.Errorf("harden: not implemented yet")
}
