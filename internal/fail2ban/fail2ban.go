// Package fail2ban reads the live fail2ban (jails, banned IPs), unbans an IP
// and edits the ignore list in vpsctl's jail drop-in. Commands go through a
// system.Runner; file paths are under a root ("" in production).
package fail2ban

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/anhvandev/vpsctl/internal/system"
)

// DropIn is vpsctl's jail drop-in, first written by `vpsctl harden`.
const DropIn = "/etc/fail2ban/jail.d/00-vpsctl.local"

var (
	ErrNotInstalled = errors.New("not installed")
	ErrNotRunning   = errors.New("not running")
)

var ignoreRe = regexp.MustCompile(`(?m)^ignoreip\s*=(.*)$`)

// Ban is one banned IP in one jail.
type Ban struct{ Jail, IP string }

// Jails lists the running jails; ErrNotInstalled or ErrNotRunning when
// fail2ban is absent or stopped.
func Jails(r system.Runner) ([]string, error) {
	res, err := r.Run("fail2ban-client", "status")
	switch {
	case err != nil:
		return nil, ErrNotInstalled
	case res.Code != 0:
		return nil, ErrNotRunning
	}
	var jails []string
	for _, j := range strings.Split(field(res.Stdout, "Jail list:"), ",") {
		if j = strings.TrimSpace(j); j != "" {
			jails = append(jails, j)
		}
	}
	return jails, nil
}

// Bans lists the banned IPs of jails, in jail order; unreadable jails are skipped.
func Bans(r system.Runner, jails []string) []Ban {
	var bans []Ban
	for _, j := range jails {
		res, err := r.Run("fail2ban-client", "status", j)
		if err != nil || res.Code != 0 {
			continue
		}
		for _, ip := range strings.Fields(field(res.Stdout, "Banned IP list:")) {
			bans = append(bans, Ban{j, ip})
		}
	}
	return bans
}

// Unban lifts b.
func Unban(r system.Runner, b Ban) error {
	return run(r, "fail2ban-client", "set", b.Jail, "unbanip", b.IP)
}

// Ignore is the ignoreip list of the drop-in under root (nil if none).
func Ignore(root string) []string {
	b, _ := os.ReadFile(filepath.Join(root, DropIn))
	if sub := ignoreRe.FindSubmatch(b); sub != nil {
		return strings.Fields(string(sub[1]))
	}
	return nil
}

// WithIgnore is drop-in content s with entries added to its first ignoreip
// line, keeping the ones already there; without one it adds a [DEFAULT]
// ignoreip for all jails. No entries leaves s as is.
func WithIgnore(s string, entries ...string) string {
	if len(entries) == 0 {
		return s
	}
	if loc := ignoreRe.FindStringSubmatchIndex(s); loc != nil {
		list := strings.Fields(s[loc[2]:loc[3]])
		for _, e := range entries {
			if !slices.Contains(list, e) {
				list = append(list, e)
			}
		}
		return s[:loc[0]] + "ignoreip = " + strings.Join(list, " ") + s[loc[1]:]
	}
	return "[DEFAULT]\nignoreip = " + strings.Join(entries, " ") + "\n\n" + s
}

// AddIgnore adds entry (an IP or CIDR) to the drop-in's ignore list under
// root and reloads fail2ban.
func AddIgnore(r system.Runner, root, entry string) error {
	if !ValidIgnore(entry) {
		return fmt.Errorf("%q is not an IP or CIDR", entry)
	}
	p := filepath.Join(root, DropIn)
	b, err := os.ReadFile(p)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte(WithIgnore(string(b), entry)), 0o644); err != nil {
		return err
	}
	return run(r, "fail2ban-client", "reload")
}

// ValidIgnore reports whether s is an IP address or CIDR.
func ValidIgnore(s string) bool {
	_, errA := netip.ParseAddr(s)
	_, errP := netip.ParsePrefix(s)
	return errA == nil || errP == nil
}

// field is the value after label in fail2ban-client's tree output.
func field(out, label string) string {
	for _, line := range strings.Split(out, "\n") {
		if _, v, ok := strings.Cut(line, label); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// run is r.Run with a non-zero exit turned into an error.
func run(r system.Runner, name string, args ...string) error {
	res, err := r.Run(name, args...)
	if err == nil && res.Code != 0 {
		err = fmt.Errorf("%s %s: exit %d: %s", name, strings.Join(args, " "), res.Code, strings.TrimSpace(res.Stderr))
	}
	return err
}
