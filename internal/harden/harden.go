// Package harden orchestrates Hardening: Admin User + key, firewall, the
// two-stage SSH change around the Verify Gate, then the lock-down extras.
// Ordering lives here only; the modules never call each other's flow.
package harden

import (
	"cmp"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/anhvandev/vpsctl/internal/firewall"
	"github.com/anhvandev/vpsctl/internal/system"
)

// Options are the `vpsctl harden` flags.
type Options struct {
	User                                                string
	Port                                                int // 0 = keep the current SSH port
	Yes                                                 bool
	KeyOut                                              string
	RotateKey                                           bool
	SkipFirewall, SkipFail2ban, SkipUpdates, SkipSysctl bool
}

// ParseFlags parses `vpsctl harden` arguments and rejects unsafe combinations.
func ParseFlags(args []string) (Options, error) {
	var o Options
	fs := flag.NewFlagSet("harden", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.User, "user", "", "Admin User to create (required)")
	fs.IntVar(&o.Port, "port", 0, "move SSH to this port (default: keep current)")
	fs.BoolVar(&o.Yes, "yes", false, "skip the saved-key and Verify Gate prompts (pre-lock assertions still run)")
	fs.StringVar(&o.KeyOut, "key-out", "", "write the private key to this file (mode 600) instead of the TTY")
	fs.BoolVar(&o.RotateKey, "rotate-key", false, "generate and install a new key")
	fs.BoolVar(&o.SkipFirewall, "skip-firewall", false, "do not manage ufw/firewalld")
	fs.BoolVar(&o.SkipFail2ban, "skip-fail2ban", false, "do not set up fail2ban")
	fs.BoolVar(&o.SkipUpdates, "skip-updates", false, "do not set up automatic security updates")
	fs.BoolVar(&o.SkipSysctl, "skip-sysctl", false, "do not apply the sysctl drop-in")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	switch {
	case fs.NArg() > 0:
		return o, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	case o.User == "":
		return o, errors.New("--user NAME is required")
	case o.Port < 0 || o.Port > 65535:
		return o, errors.New("--port must be 1-65535")
	case o.Port != 0 && o.SkipFirewall:
		return o, errors.New("--port cannot be combined with --skip-firewall (the firewall would block the new SSH port)")
	}
	return o, nil
}

// LogDir holds the timestamped Hardening logs.
const LogDir = "/var/log/vpsctl"

// OpenLog creates a new timestamped Hardening log (mode 600) under root's LogDir.
func OpenLog(root string) (*os.File, error) {
	dir := filepath.Join(root, LogDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	name := filepath.Join(dir, "harden-"+time.Now().Format("20060102-150405")+".log")
	return os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
}

// Host is everything Hardening does to the machine (*Machine in production).
type Host interface {
	EnsureAdmin(name string) error
	InstallKey(name, keyOut string, rotate, waitSaved bool) error
	CurrentPort() (int, error)
	// EnsureFirewall returns nil, nil when the distro has no managed firewall.
	EnsureFirewall(sshPort int) (firewall.Backend, error)
	BeginSSH(fw firewall.Backend, port int, user string) (Change, Plan, error)
	PreLockAssertions(user string) error
	LockDefaultCloudUsers() error
	BlockCloudInitReinjection() error
	Fail2ban(sshPort int) error
	AutoUpdates() error
	Sysctl() error
	SaveRecord(Record) error
}

// Change is a snapshotted SSH change (*sshd.Change). StageA/StageB restore on
// their own failures; Run calls Restore for its own failures in between.
type Change interface {
	StageA() error
	StageB() error
	Restore() error
}

// Plan is what BeginSSH found: the pre-run port, the target port and
// whether auth hardening was already live.
type Plan struct {
	OldPort, Port int
	StageBLive    bool
}

// ErrStopped: the operator stopped at the Verify Gate (exit 3).
var ErrStopped = errors.New("stopped at the Verify Gate")

// Run hardens h. ask prompts the operator at the Verify Gate (unused with
// o.Yes); an error from ask (no TTY) aborts. out never sees the private key.
func Run(o Options, h Host, out io.Writer, ask func(question string) (bool, error)) error {
	info := func(f string, a ...any) { fmt.Fprintf(out, "[*] "+f+"\n", a...) }
	warn := func(f string, a ...any) { fmt.Fprintf(out, "[!] "+f+"\n", a...) }

	// The Hardening Record, saved once the run succeeds.
	rec := Record{Ran: time.Now(), By: cmp.Or(system.SessionUser(), "root"), Admin: o.User, Applied: map[string]time.Time{}}
	applied := func(ids ...string) {
		for _, id := range ids {
			rec.Applied[id] = time.Now()
		}
	}
	for id, skip := range map[string]bool{"firewall": o.SkipFirewall, "fail2ban": o.SkipFail2ban, "updates": o.SkipUpdates, "sysctl": o.SkipSysctl} {
		if skip {
			rec.Skipped = append(rec.Skipped, id)
		}
	}
	slices.Sort(rec.Skipped)

	info("ensuring Admin User %q", o.User)
	if err := h.EnsureAdmin(o.User); err != nil {
		return err
	}
	if err := h.InstallKey(o.User, o.KeyOut, o.RotateKey, !o.Yes); err != nil {
		return err
	}
	applied("admin")

	p, err := ChangeSSH(o, h, out, ask)
	if err != nil {
		return err
	}
	applied("ssh", "port")
	if !o.SkipFirewall {
		applied("firewall")
	}

	info("locking Default Cloud Users")
	if err := h.LockDefaultCloudUsers(); err != nil {
		return err
	}
	if err := h.BlockCloudInitReinjection(); err != nil {
		return err
	}
	applied("cloud-users", "cloud-init")

	// Extras never undo the SSH hardening already applied: warn and go on.
	extra := func(skip bool, name string, f func() error) {
		if skip {
			warn("--skip-%s", name)
		} else if err := f(); err != nil {
			warn("%s: %v (continuing)", name, err)
		} else {
			info("%s configured", name)
			applied(name)
		}
	}
	extra(o.SkipFail2ban, "fail2ban", func() error { return h.Fail2ban(p.Port) })
	extra(o.SkipUpdates, "updates", h.AutoUpdates)
	extra(o.SkipSysctl, "sysctl", h.Sysctl)
	if err := h.SaveRecord(rec); err != nil {
		warn("Hardening Record not saved: %v", err)
	}

	fmt.Fprintf(out, "\n== SUMMARY ==\n  admin user : %s (key-only SSH, NOPASSWD sudo)\n  ssh port   : %d\n"+
		"  password auth, root login: disabled\n  default cloud users: locked\nLost the key? Re-run with --rotate-key.\n",
		o.User, p.Port)
	return nil
}

// ChangeSSH is Hardening's SSH part, also run alone by the TUI to change the
// port: firewall (current SSH port allowed first), Stage A, the Verify Gate,
// pre-lock assertions for o.User, Stage B. Any failure after the first
// mutation restores the snapshot; ErrStopped when the operator stops at the
// gate. o.Port 0 keeps the current port.
func ChangeSSH(o Options, h Host, out io.Writer, ask func(question string) (bool, error)) (Plan, error) {
	info := func(f string, a ...any) { fmt.Fprintf(out, "[*] "+f+"\n", a...) }
	warn := func(f string, a ...any) { fmt.Fprintf(out, "[!] "+f+"\n", a...) }

	var fw firewall.Backend
	if o.SkipFirewall {
		warn("--skip-firewall: firewall not managed")
	} else {
		cur, err := h.CurrentPort()
		if err != nil {
			return Plan{}, err
		}
		info("ensuring firewall (allowing current SSH port %d first)", cur)
		if fw, err = h.EnsureFirewall(cur); err != nil {
			return Plan{}, err
		}
		if fw == nil {
			warn("no managed firewall for this distro: skipping")
		}
	}

	c, p, err := h.BeginSSH(fw, o.Port, o.User)
	if err != nil {
		return p, err
	}
	info("SSH port: %d (was %d)", p.Port, p.OldPort)
	restore := func(err error) error {
		if rerr := c.Restore(); rerr != nil {
			return fmt.Errorf("%w; restore also failed: %w", err, rerr)
		}
		return fmt.Errorf("%w (restored pre-run SSH state)", err)
	}

	if p.StageBLive && p.Port == p.OldPort {
		info("already hardened and port unchanged: skipping Stage A and the Verify Gate")
	} else {
		info("Stage A: SSH on port %d, password auth still on", p.Port)
		if err := c.StageA(); err != nil {
			return p, err
		}
		fmt.Fprintf(out, "\n== VERIFY GATE ==\nFrom your local machine, in a NEW terminal (keep this session open!):\n"+
			"  ssh -i <saved-key> -p %d %s@<this-host>\nThen confirm sudo works:  sudo true\n\n", p.Port, o.User)
		if o.Yes {
			warn("--yes: skipping the Verify Gate prompt (pre-lock assertions still run)")
		} else {
			ok, err := ask("Did the NEW login work?")
			if err != nil {
				return p, restore(fmt.Errorf("verify gate: %w (use --yes for automation)", err))
			}
			if !ok {
				return p, restore(ErrStopped)
			}
		}
	}

	if err := h.PreLockAssertions(o.User); err != nil {
		return p, restore(fmt.Errorf("pre-lock assertion failed: %w", err))
	}
	info("Stage B: disabling password and root login")
	if err := c.StageB(); err != nil {
		return p, err
	}
	return p, nil
}
