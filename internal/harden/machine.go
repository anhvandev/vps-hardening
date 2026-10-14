package harden

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/anhvandev/vpsctl/internal/firewall"
	"github.com/anhvandev/vpsctl/internal/sshd"
	"github.com/anhvandev/vpsctl/internal/system"
	"github.com/anhvandev/vpsctl/internal/user"
)

// Machine is the real Host: it wires internal/user, internal/firewall and
// internal/sshd over one Runner and one shared Packages, and implements the
// pre-lock assertions and the lock-down extras. Root prefixes every file path
// ("" in production).
type Machine struct {
	*user.Manager // EnsureAdmin, InstallKey, LockDefaultCloudUsers, BlockCloudInitReinjection
	SSH           *sshd.Manager
	R             system.Runner
	Host          system.Host
	Root          string
	Pkgs          *system.Packages
}

// NewMachine wires the modules; warnings go to out.
func NewMachine(r system.Runner, h system.Host, root string, out io.Writer) *Machine {
	pkgs := &system.Packages{R: r, Manager: h.PkgManager}
	return &Machine{
		Manager: &user.Manager{R: r, Host: h, Pkgs: pkgs, Root: root},
		SSH: &sshd.Manager{R: r, Host: h, Pkgs: pkgs, Root: root,
			Warn: func(s string) { fmt.Fprintln(out, "[!]", s) }},
		R: r, Host: h, Root: root, Pkgs: pkgs,
	}
}

func (m *Machine) CurrentPort() (int, error) { return m.SSH.CurrentPort() }

func (m *Machine) EnsureFirewall(sshPort int) (firewall.Backend, error) {
	fw, err := firewall.New(m.Host, m.R, m.Pkgs)
	if errors.Is(err, firewall.ErrNoBackend) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return fw, fw.Ensure(sshPort)
}

func (m *Machine) BeginSSH(fw firewall.Backend, port int, user string) (Change, Plan, error) {
	c, err := m.SSH.Begin(fw, port, user)
	if err != nil {
		return nil, Plan{}, err
	}
	return c, Plan{OldPort: c.OldPort, Port: c.Port, StageBLive: c.StageBLive}, nil
}

// PreLockAssertions proves name can still get in and escalate before
// password auth goes away: pubkey auth effective for name, a non-empty
// authorized_keys (600, owned by name), and `sudo -n` working as name.
func (m *Machine) PreLockAssertions(name string) error {
	out, err := m.SSH.Effective("-C", "user="+name+",host=localhost,addr=127.0.0.1")
	if err != nil {
		return err
	}
	if !regexp.MustCompile(`(?m)^pubkeyauthentication yes$`).MatchString(out) {
		return fmt.Errorf("pubkey auth not effective for %s", name)
	}
	pw, err := m.output("getent", "passwd", name)
	if err != nil {
		return err
	}
	f := strings.Split(strings.TrimSpace(pw), ":")
	if len(f) < 7 {
		return fmt.Errorf("getent passwd %s: %q", name, pw)
	}
	uid, err := strconv.Atoi(f[2])
	if err != nil {
		return fmt.Errorf("getent passwd %s: %q", name, pw)
	}
	ak := filepath.Join(f[5], ".ssh/authorized_keys")
	fi, err := os.Stat(filepath.Join(m.Root, ak))
	if err != nil {
		return err
	}
	st, _ := fi.Sys().(*syscall.Stat_t)
	if fi.Size() == 0 || fi.Mode().Perm() != 0o600 || st == nil || int(st.Uid) != uid {
		return fmt.Errorf("%s must be non-empty, mode 600 and owned by %s", ak, name)
	}
	if _, err := m.output("sudo", "-u", name, "sudo", "-n", "true"); err != nil {
		return fmt.Errorf("%s cannot sudo without a password: %w", name, err)
	}
	return nil
}

// Fail2ban installs fail2ban and enables an sshd jail on sshPort with a
// banaction matching the live firewall.
func (m *Machine) Fail2ban(sshPort int) error {
	if _, err := m.R.Run("fail2ban-client", "--version"); err != nil {
		if m.Host.PkgManager == "dnf" {
			m.Pkgs.Install("epel-release") // fail2ban lives in EPEL; may already be enabled
		}
		if err := m.Pkgs.Install("fail2ban"); err != nil {
			return err
		}
	}
	banaction := "iptables-multiport" // Ubuntu 22.04's fail2ban 0.11 lacks nftables-*
	if m.ok("systemctl", "is-active", "--quiet", "firewalld") {
		banaction = "firewallcmd-ipset"
	} else if _, err := m.R.Run("nft", "--version"); err == nil {
		banaction = "nftables-multiport"
	}
	jail := fmt.Sprintf("[sshd]\nenabled = true\nport = %d\nbanaction = %s\n", sshPort, banaction)
	// Cloud images often have no syslog file for the default backend.
	if m.Host.Family != "debian" || !m.ok("systemctl", "is-enabled", "--quiet", "rsyslog.service") {
		jail += "backend = systemd\n"
	}
	if err := m.writeFile("/etc/fail2ban/jail.d/00-vpsctl.local", jail); err != nil {
		return err
	}
	if _, err := m.output("systemctl", "enable", "fail2ban"); err != nil {
		return err
	}
	_, err := m.output("systemctl", "restart", "fail2ban")
	return err
}

// AutoUpdates enables security-only automatic updates, never rebooting.
func (m *Machine) AutoUpdates() error {
	switch m.Host.PkgManager {
	case "apt":
		if !m.ok("dpkg", "-s", "unattended-upgrades") {
			if err := m.Pkgs.Install("unattended-upgrades"); err != nil {
				return err
			}
		}
		if err := m.writeFile("/etc/apt/apt.conf.d/20auto-upgrades",
			"APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\nAPT::Periodic::AutocleanInterval \"7\";\n"); err != nil {
			return err
		}
		// Sorts after 50unattended-upgrades: #clear drops its origins (Debian's
		// include the whole stable archive) so only the security pocket remains.
		if err := m.writeFile("/etc/apt/apt.conf.d/52vpsctl-unattended-upgrades", `// Managed by vpsctl: security updates only, never reboot.
#clear Unattended-Upgrade::Allowed-Origins;
#clear Unattended-Upgrade::Origins-Pattern;
Unattended-Upgrade::Origins-Pattern {
	"origin=${distro_id},archive=${distro_codename}-security";
	"origin=${distro_id},codename=${distro_codename}-security";
};
Unattended-Upgrade::Automatic-Reboot "false";
`); err != nil {
			return err
		}
		_, err := m.output("systemctl", "enable", "--now", "apt-daily.timer", "apt-daily-upgrade.timer")
		return err
	case "dnf":
		if !m.ok("rpm", "-q", "dnf-automatic") {
			if err := m.Pkgs.Install("dnf-automatic"); err != nil {
				return err
			}
		}
		p := filepath.Join(m.Root, "/etc/dnf/automatic.conf")
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		// dnf-automatic never reboots unless `reboot` is set; force it off where present.
		for k, v := range map[string]string{"upgrade_type": "security", "apply_updates": "yes", "reboot": "never"} {
			re := regexp.MustCompile(`(?m)^` + k + `\s*=.*$`)
			if k != "reboot" && !re.Match(b) {
				return fmt.Errorf("/etc/dnf/automatic.conf: no %s setting", k)
			}
			b = re.ReplaceAll(b, []byte(k+" = "+v))
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			return err
		}
		_, err = m.output("systemctl", "enable", "--now", "dnf-automatic.timer")
		return err
	}
	return fmt.Errorf("not managed for package manager %q", m.Host.PkgManager)
}

// Sysctl writes the network/kernel hardening drop-in and loads it.
func (m *Machine) Sysctl() error {
	if err := m.writeFile("/etc/sysctl.d/90-vpsctl.conf", `# Managed by vpsctl
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
kernel.kptr_restrict = 2
`); err != nil {
		return err
	}
	if _, err := m.output("sysctl", "--system"); err != nil {
		return fmt.Errorf("drop-in written but not loaded (container without /proc write?): %w", err)
	}
	return nil
}

func (m *Machine) writeFile(p, s string) error {
	p = filepath.Join(m.Root, p)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(s), 0o644)
}

func (m *Machine) ok(name string, args ...string) bool {
	_, err := m.output(name, args...)
	return err == nil
}

func (m *Machine) output(name string, args ...string) (string, error) {
	res, err := m.R.Run(name, args...)
	if err == nil && res.Code != 0 {
		err = fmt.Errorf("exit %d: %s", res.Code, strings.TrimSpace(res.Stderr))
	}
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return res.Stdout, nil
}
