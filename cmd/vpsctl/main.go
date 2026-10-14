// Command vpsctl hardens and manages a single VPS. Run as root on the VPS.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

const (
	lockPath = "/run/vpsctl.lock"
	logDir   = "/var/log/vpsctl"
)

const usage = `usage: vpsctl harden --user NAME [--port N] [--yes] [--key-out PATH] [--rotate-key]
                     [--skip-firewall] [--skip-fail2ban] [--skip-updates] [--skip-sysctl]
       vpsctl version`

func main() {
	if len(os.Args) < 2 {
		fmt.Println("vpsctl: TUI not implemented yet; use `vpsctl harden`")
		return
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(version)
	case "harden":
		os.Exit(runHarden(os.Args[2:]))
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
}

// runHarden returns the exit code: 0 ok, 1 error, 2 usage, 3 stopped at the Verify Gate.
func runHarden(args []string) int {
	o, err := harden.ParseFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n%s\n", err, usage)
		return 2
	}
	if err := system.Preflight(os.Geteuid(), "/run/systemd/system"); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		return 1
	}
	lk, err := lock()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		return 1
	}
	defer lk.Close()

	// The log never sees the private key: it goes straight to the TTY or --key-out.
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		return 1
	}
	logPath := fmt.Sprintf("%s/harden-%s.log", logDir, time.Now().Format("20060102-150405"))
	logf, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		return 1
	}
	defer logf.Close()
	out, errOut := io.MultiWriter(os.Stdout, logf), io.MultiWriter(os.Stderr, logf)
	fmt.Fprintln(out, "[*] logging to", logPath)

	err = hardenHost(o, out)
	result, code := "ok", 0
	switch {
	case errors.Is(err, harden.ErrStopped):
		fmt.Fprintf(errOut, "[!] %v: password auth still enabled, nothing locked; re-run when the new login works\n", err)
		result, code = "stopped", 3
	case err != nil:
		fmt.Fprintln(errOut, "ERROR:", err)
		result, code = "failed", 1
	}
	logAction("harden "+strings.Join(args, " "), result)
	return code
}

func hardenHost(o harden.Options, out io.Writer) error {
	h, err := system.Detect(system.Exec{}, "/etc/os-release")
	if err != nil {
		return err
	}
	if !h.Supported {
		fmt.Fprintf(out, "[!] distro %q version %q not in the supported set; proceeding best-effort\n", h.DistroID, h.Version)
	}
	fmt.Fprintf(out, "[*] distro %s (family %s), ssh unit %s, socket %q, selinux %v\n",
		h.DistroID, h.Family, h.SSHUnit, h.SSHSocket, h.SELinux)
	return harden.Run(o, harden.NewMachine(system.Exec{}, h, "", out), out, askTTY)
}

// askTTY asks a yes/no question on the controlling terminal (not stdin).
func askTTY(question string) (bool, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false, fmt.Errorf("no controlling TTY: %w", err)
	}
	defer tty.Close()
	fmt.Fprintf(tty, "%s [y/N] ", question)
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil && line == "" {
		return false, err
	}
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes", nil
}

// lock takes the global mutation lock; the kernel drops it when the process exits.
func lock() (*os.File, error) {
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		holder, _ := io.ReadAll(f)
		f.Close()
		return nil, fmt.Errorf("locked by %s", strings.TrimSpace(string(holder)))
	}
	f.Truncate(0)
	fmt.Fprintf(f, "%s (pid %d)\n", operator(), os.Getpid())
	return f, nil
}

// logAction appends one line to the action log; failures to log are ignored.
func logAction(action, result string) {
	f, err := os.OpenFile(logDir+"/actions.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s %s: %s\n", time.Now().Format(time.RFC3339), operator(), action, result)
}

func operator() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	return "root"
}
