// Package harden orchestrates Hardening: Admin User + key, firewall, the
// two-stage SSH change around the Verify Gate, then the lock-down extras.
// Ordering lives here only; the modules never call each other's flow.
package harden

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/anhvandev/vpsctl/internal/firewall"
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
	fs.BoolVar(&o.Yes, "yes", false, "skip the Verify Gate prompt (pre-lock assertions still run)")
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

// Host is everything Hardening does to the machine (*Machine in production).
type Host interface {
	EnsureAdmin(name string) error
	InstallKey(name, keyOut string, rotate bool) error
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

	info("ensuring Admin User %q", o.User)
	if err := h.EnsureAdmin(o.User); err != nil {
		return err
	}
	if err := h.InstallKey(o.User, o.KeyOut, o.RotateKey); err != nil {
		return err
	}

	var fw firewall.Backend
	if o.SkipFirewall {
		warn("--skip-firewall: firewall not managed")
	} else {
		cur, err := h.CurrentPort()
		if err != nil {
			return err
		}
		info("ensuring firewall (allowing current SSH port %d first)", cur)
		if fw, err = h.EnsureFirewall(cur); err != nil {
			return err
		}
		if fw == nil {
			warn("no managed firewall for this distro: skipping")
		}
	}

	c, p, err := h.BeginSSH(fw, o.Port, o.User)
	if err != nil {
		return err
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
			return err
		}
		fmt.Fprintf(out, "\n== VERIFY GATE ==\nFrom your local machine, in a NEW terminal (keep this session open!):\n"+
			"  ssh -i <saved-key> -p %d %s@<this-host>\nThen confirm sudo works:  sudo true\n\n", p.Port, o.User)
		if o.Yes {
			warn("--yes: skipping the Verify Gate prompt (pre-lock assertions still run)")
		} else {
			ok, err := ask("Did the NEW login work?")
			if err != nil {
				return restore(fmt.Errorf("verify gate: %w (use --yes for automation)", err))
			}
			if !ok {
				return restore(ErrStopped)
			}
		}
	}

	if err := h.PreLockAssertions(o.User); err != nil {
		return restore(fmt.Errorf("pre-lock assertion failed: %w", err))
	}
	info("Stage B: disabling password and root login")
	if err := c.StageB(); err != nil {
		return err
	}

	info("locking Default Cloud Users")
	if err := h.LockDefaultCloudUsers(); err != nil {
		return err
	}
	if err := h.BlockCloudInitReinjection(); err != nil {
		return err
	}

	// Extras never undo the SSH hardening already applied: warn and go on.
	extra := func(skip bool, name string, f func() error) {
		if skip {
			warn("--skip-%s", name)
		} else if err := f(); err != nil {
			warn("%s: %v (continuing)", name, err)
		} else {
			info("%s configured", name)
		}
	}
	extra(o.SkipFail2ban, "fail2ban", func() error { return h.Fail2ban(p.Port) })
	extra(o.SkipUpdates, "updates", h.AutoUpdates)
	extra(o.SkipSysctl, "sysctl", h.Sysctl)

	fmt.Fprintf(out, "\n== SUMMARY ==\n  admin user : %s (key-only SSH, NOPASSWD sudo)\n  ssh port   : %d\n"+
		"  password auth, root login: disabled\n  default cloud users: locked\nLost the key? Re-run with --rotate-key.\n",
		o.User, p.Port)
	return nil
}
