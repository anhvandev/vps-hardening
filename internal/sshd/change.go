package sshd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/anhvandev/vpsctl/internal/firewall"
)

// Change is one SSH config run: Begin snapshots, StageA/StageB apply, and
// Restore rolls everything back. StageA and StageB restore by themselves on
// failure; the caller must call Restore for its own failures in between
// (e.g. pre-lock assertions) — any failure after the first mutation restores.
type Change struct {
	m       *Manager
	fw      firewall.Backend // nil = firewall not managed
	user    string           // Admin User for the sshd -T -C probe
	OldPort int              // port sshd was configured for before the run
	Port    int              // target port
	// StageBLive: auth hardening was already live before the run. Then
	// Stage A keeps it (never downgrades); with Port == OldPort the run is a
	// hardened re-run and the Verify Gate can be skipped.
	StageBLive bool

	files map[string]*file // path (without Root) → pre-run content; nil = absent
	rules []firewall.Rule
}

type file struct {
	data []byte
	mode os.FileMode
}

// Begin snapshots sshd config, drop-ins, the socket drop-in and (when fw is
// non-nil) the firewall rules. Call it after fw.Ensure: List needs a running
// firewall. port 0 keeps the current port. Begin changes no config (it may
// generate missing host keys, which sshd -T needs).
func (m *Manager) Begin(fw firewall.Backend, port int, user string) (*Change, error) {
	old, err := m.CurrentPort()
	if err != nil {
		return nil, err
	}
	if port == 0 {
		port = old
	}
	c := &Change{m: m, fw: fw, user: user, OldPort: old, Port: port, StageBLive: m.StageBLive(), files: map[string]*file{}}
	paths, _ := filepath.Glob(m.path(DropInDir + "/*.conf"))
	for i, p := range paths {
		paths[i] = p[len(m.Root):]
	}
	paths = append(paths, MainConfig, DropIn)
	if m.Host.SSHSocket != "" {
		paths = append(paths, m.socketDropIn())
	}
	for _, p := range paths {
		b, err := os.ReadFile(m.path(p))
		if errors.Is(err, os.ErrNotExist) {
			c.files[p] = nil
			continue
		}
		if err != nil {
			return nil, err
		}
		fi, err := os.Stat(m.path(p))
		if err != nil {
			return nil, err
		}
		c.files[p] = &file{b, fi.Mode().Perm()}
	}
	if fw != nil {
		if c.rules, err = fw.List(); err != nil {
			return nil, err
		}
		// The pre-run SSH port is always part of the state to restore.
		if !slices.Contains(c.rules, tcp(old)) {
			c.rules = append(c.rules, tcp(old))
		}
	}
	return c, nil
}

func tcp(port int) firewall.Rule { return firewall.Rule{Port: port, Proto: "tcp"} }

func (c *Change) portChanged() bool { return c.Port != c.OldPort }

// StageA writes the Port (keeping auth hardening if already live), validates,
// opens the new port in the firewall and applies. Restores on failure.
func (c *Change) StageA() error {
	return c.restoreOnError(func() error {
		m := c.m
		if err := m.ensureInclude(); err != nil {
			return err
		}
		if err := m.neutralizeForeignPorts(); err != nil {
			return err
		}
		changed, err := m.write(c.Port, c.StageBLive)
		if err != nil {
			return err
		}
		user := ""
		if c.StageBLive {
			user = c.user
		}
		if err := m.validate(c.Port, user); err != nil {
			return err
		}
		m.scanMatch()
		// Open the new port BEFORE sshd moves to it; the old one stays open.
		if c.portChanged() && c.fw != nil {
			if err := c.fw.Allow(tcp(c.Port)); err != nil {
				return err
			}
		}
		if changed || c.portChanged() {
			return m.apply(c.Port, c.portChanged())
		}
		return nil
	})
}

// StageB (after the Verify Gate) adds auth hardening, validates it globally
// and for the Admin User, applies, and only then closes the old SSH port —
// only the rules opening it to anyone. Restores on failure.
func (c *Change) StageB() error {
	return c.restoreOnError(func() error {
		m := c.m
		changed, err := m.write(c.Port, true)
		if err != nil {
			return err
		}
		if err := m.validate(c.Port, c.user); err != nil {
			return err
		}
		if changed || c.portChanged() {
			if err := m.apply(c.Port, c.portChanged()); err != nil {
				return err
			}
		}
		if !c.portChanged() {
			return nil
		}
		if m.listening(c.OldPort) {
			m.warn(fmt.Sprintf("old port %d is still listening: check for foreign Port directives", c.OldPort))
		}
		if c.fw == nil {
			return nil
		}
		if err := c.fw.Remove(tcp(c.OldPort)); err != nil {
			return err
		}
		// Also the other forms that open it to anyone (ufw `allow <port>`,
		// `limit <port>/tcp`); source-limited and other ports' rules stay.
		for _, r := range c.rules {
			if r != tcp(c.OldPort) && r.Port == c.OldPort && r.End == 0 && r.From == "" && r.Proto != "udp" {
				if err := c.fw.Remove(r); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// ErrRestored marks an error after which the SSH change was rolled back:
// files, sshd and the firewall are as before it.
var ErrRestored = errors.New("restored pre-run SSH state")

func (c *Change) restoreOnError(f func() error) error {
	if err := f(); err != nil {
		if rerr := c.Restore(); rerr != nil {
			return fmt.Errorf("%w; restore also failed: %w", err, rerr)
		}
		return fmt.Errorf("%w (%w)", err, ErrRestored)
	}
	return nil
}

// Restore brings files, sshd and the firewall back to the snapshot. The
// pre-run SSH port is re-allowed first, and rules added by the run are
// removed only once sshd listens on the pre-run port again, so a rollback
// never leaves zero SSH ports allowed. Best effort: every step runs.
func (c *Change) Restore() error {
	m := c.m
	var errs []error
	if c.fw != nil {
		if rules, err := c.fw.List(); err != nil || !slices.Contains(rules, tcp(c.OldPort)) {
			errs = append(errs, err, c.fw.Allow(tcp(c.OldPort)))
		}
	}
	dirty := false
	for p, f := range c.files {
		cur, err := os.ReadFile(m.path(p))
		switch {
		case f == nil && err == nil:
			dirty = true
			errs = append(errs, os.Remove(m.path(p)))
		case f != nil && (err != nil || !bytes.Equal(cur, f.data)):
			dirty = true
			errs = append(errs, writeFile(m.path(p), f.data, f.mode))
		}
	}
	sshdOK := true
	if dirty {
		var err error
		if m.Host.SSHSocket != "" {
			errs = append(errs, m.run("systemctl", "daemon-reload"))
			err = m.restartSocket()
		} else {
			err = m.run("systemctl", "restart", m.Host.SSHUnit)
		}
		if err == nil {
			err = m.verifyListener(c.OldPort)
		}
		sshdOK = err == nil
		errs = append(errs, err)
	}
	if c.fw != nil {
		if sshdOK {
			errs = append(errs, firewall.Restore(c.fw, c.rules))
		} else {
			errs = append(errs, errors.New("sshd not back on the pre-run port: keeping the run's firewall rules open"))
		}
	}
	return errors.Join(errs...)
}
