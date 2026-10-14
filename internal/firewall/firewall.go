// Package firewall drives the host firewall: ufw on the debian family,
// firewalld on the rhel family. The live system is the source of truth.
package firewall

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/anhvandev/vpsctl/internal/system"
)

// Rule is a Firewall Rule: an allow entry for a port or port range.
type Rule struct {
	Port  int
	End   int    // last port of a range; 0 = single port
	Proto string // "tcp", "udp", or "" = both (ufw only)
	From  string // source IP/CIDR; "" = anywhere
}

// Backend is one host firewall implementation. Allow and Remove act on
// exactly the given rule; nothing else is touched.
type Backend interface {
	// Ensure installs the firewall if missing, allows sshPort/tcp (the port
	// SSH listens on NOW), and only then enables the firewall.
	Ensure(sshPort int) error
	List() ([]Rule, error)
	Allow(Rule) error
	Remove(Rule) error
}

// validate guards input from the operator (TUI/CLI) before it reaches the host.
func (r Rule) validate() error {
	end := r.End
	if end == 0 {
		end = r.Port
	}
	if r.Port < 1 || end < r.Port || end > 65535 {
		return fmt.Errorf("invalid port range %d-%d", r.Port, r.End)
	}
	if r.Proto != "" && r.Proto != "tcp" && r.Proto != "udp" {
		return fmt.Errorf("invalid protocol %q", r.Proto)
	}
	if r.From != "" {
		if _, err := netip.ParsePrefix(r.From); err != nil {
			if _, err := netip.ParseAddr(r.From); err != nil {
				return fmt.Errorf("invalid source %q", r.From)
			}
		}
	}
	return nil
}

// ports formats the port or range with sep ("6000:6100" for ufw, "-" for firewalld).
func (r Rule) ports(sep string) string {
	if r.End == 0 {
		return strconv.Itoa(r.Port)
	}
	return fmt.Sprintf("%d%s%d", r.Port, sep, r.End)
}

// parsePorts is the inverse of Rule.ports.
func parsePorts(s, sep string) (port, end int, ok bool) {
	a, b, isRange := strings.Cut(s, sep)
	port, err := strconv.Atoi(a)
	if err != nil {
		return 0, 0, false
	}
	if isRange {
		if end, err = strconv.Atoi(b); err != nil {
			return 0, 0, false
		}
	}
	return port, end, true
}

// ErrNoBackend: the host family has no managed firewall (best-effort skip).
var ErrNoBackend = errors.New("no managed firewall for this distro family")

// New picks the backend for h.Family.
func New(h system.Host, r system.Runner, p *system.Packages) (Backend, error) {
	switch h.Family {
	case "debian":
		return &ufw{r: r, p: p}, nil
	case "rhel":
		return &firewalld{r: r, p: p}, nil
	}
	return nil, ErrNoBackend
}

// Restore brings b back to snapshot (a List result taken earlier). Missing
// rules are re-allowed first; extra rules are removed only if every re-allow
// succeeded, so a rollback never leaves fewer ports open than the snapshot.
func Restore(b Backend, snapshot []Rule) error {
	current, err := b.List()
	if err != nil {
		return err
	}
	var errs []error
	for _, r := range snapshot {
		if !slices.Contains(current, r) {
			errs = append(errs, b.Allow(r))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	for _, r := range current {
		if !slices.Contains(snapshot, r) {
			errs = append(errs, b.Remove(r))
		}
	}
	return errors.Join(errs...)
}

// run fails on a non-zero exit as well as on a command that could not start.
func run(r system.Runner, name string, args ...string) (string, error) {
	res, err := r.Run(name, args...)
	if err == nil && res.Code != 0 {
		err = fmt.Errorf("exit %d: %s", res.Code, strings.TrimSpace(res.Stderr+" "+res.Stdout))
	}
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return res.Stdout, nil
}
