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

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/actionlog"
	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
	"github.com/anhvandev/vpsctl/internal/tui"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

const logDir = "/var/log/vpsctl"

// lock takes the shared global mutation lock.
var lock = actionlog.Lock

const usage = `usage: vpsctl                 (management TUI)
       vpsctl harden --user NAME [--port N] [--yes] [--key-out PATH] [--rotate-key]
                     [--skip-firewall] [--skip-fail2ban] [--skip-updates] [--skip-sysctl]
       vpsctl version`

func main() {
	if len(os.Args) < 2 {
		os.Exit(runTUI())
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

// runTUI opens the management TUI after the root + systemd preflight.
func runTUI() int {
	if err := system.Preflight(os.Geteuid(), "/run/systemd/system"); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		return 1
	}
	h, err := system.Detect(system.Exec{}, "/etc/os-release")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		return 1
	}
	m := harden.NewMachine(system.Exec{}, h, "", io.Discard)
	if _, err := tea.NewProgram(tui.New(m)).Run(); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		return 1
	}
	return 0
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
	lk, err := lock(actionlog.LockPath)
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
	actionlog.Append(actionlog.LogPath, "harden "+strings.Join(args, " "), result) // failures to log are ignored
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
	return ask(tty, question)
}

// tcflsh is TCFLSH on linux amd64/arm64 (missing from syscall on amd64).
const tcflsh = 0x540b

// ask prints question on tty and reads the answer. Keys typed earlier
// (e.g. Enter while harden was busy) are discarded first so they can't
// answer the question.
func ask(tty *os.File, question string) (bool, error) {
	syscall.Syscall(syscall.SYS_IOCTL, tty.Fd(), tcflsh, syscall.TCIFLUSH)
	fmt.Fprintf(tty, "%s [y/N] ", question)
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil && line == "" {
		return false, err
	}
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes", nil
}
