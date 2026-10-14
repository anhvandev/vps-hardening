// Package sshd changes the SSH daemon config through a vpsctl-owned drop-in,
// in two stages: Stage A sets only the Port, Stage B adds auth hardening
// (after the Verify Gate). A Change snapshots everything it may touch and
// restores it on any failure. The daemon is restarted, never reloaded
// (Debian 13 socket bug #1128329).
package sshd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/anhvandev/vpsctl/internal/system"
)

const (
	MainConfig = "/etc/ssh/sshd_config"
	DropInDir  = "/etc/ssh/sshd_config.d"
	DropIn     = DropInDir + "/00-vpsctl.conf" // 00-: sshd is first-match, ours wins
	include    = "Include /etc/ssh/sshd_config.d/*.conf"
)

// Manager does sshd work on one host. Root prefixes every file path it
// touches ("" in production). Pkgs installs semanage when SELinux needs it.
// Sleep paces listener retries (nil = time.Sleep); Warn receives non-fatal
// findings such as Match blocks (nil = dropped).
type Manager struct {
	R     system.Runner
	Host  system.Host
	Pkgs  *system.Packages
	Root  string
	Sleep func(time.Duration)
	Warn  func(string)
}

// socketDropIn is the manual ListenStream override for the host's socket unit.
func (m *Manager) socketDropIn() string {
	return "/etc/systemd/system/" + m.Host.SSHSocket + ".d/99-vpsctl-listen.conf"
}

func (m *Manager) path(p string) string { return filepath.Join(m.Root, p) }

func (m *Manager) warn(s string) {
	if m.Warn != nil {
		m.Warn(s)
	}
}

// CurrentPort is the port sshd is configured for now (first `port` of sshd -T).
func (m *Manager) CurrentPort() (int, error) {
	out, err := m.Effective()
	if err != nil {
		return 0, err
	}
	if ports := values(out, "port"); len(ports) > 0 {
		return strconv.Atoi(ports[0])
	}
	return 0, errors.New("sshd -T reports no port")
}

// StageBLive reports whether the vpsctl drop-in already carries auth hardening.
func (m *Manager) StageBLive() bool {
	b, _ := os.ReadFile(m.path(DropIn))
	return regexp.MustCompile(`(?m)^PasswordAuthentication no$`).Match(b)
}

// ensureInclude prepends the Include line: drop-ins only count when included.
func (m *Manager) ensureInclude() error {
	p := m.path(MainConfig)
	b, err := os.ReadFile(p)
	if err != nil {
		return fmt.Errorf("%s: %w (is openssh-server installed?)", MainConfig, err)
	}
	if regexp.MustCompile(`(?mi)^[ \t]*Include[ \t]+/etc/ssh/sshd_config\.d/\*\.conf`).Match(b) {
		return nil
	}
	m.warn("Include directive missing in " + MainConfig + ": prepending")
	return writeFile(p, append([]byte(include+"\n"), b...), 0o644)
}

var portLine = regexp.MustCompile(`(?mi)^([ \t]*Port[ \t].*)$`)

// neutralizeForeignPorts comments out Port lines outside our drop-in: Port
// accumulates across files, so a foreign one would add a second listener.
func (m *Manager) neutralizeForeignPorts() error {
	files, _ := filepath.Glob(m.path(DropInDir + "/*.conf"))
	for _, f := range append(files, m.path(MainConfig)) {
		if f == m.path(DropIn) {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil || !portLine.Match(b) {
			continue
		}
		m.warn("commenting out Port in " + strings.TrimPrefix(f, m.Root) + " (managed in " + DropIn + ")")
		if err := writeFile(f, portLine.ReplaceAll(b, []byte("# vpsctl: disabled (managed in 00-vpsctl.conf) $1")), 0); err != nil {
			return err
		}
	}
	return nil
}

// write renders the drop-in for port; stageB adds auth hardening. Reports
// whether the file changed.
func (m *Manager) write(port int, stageB bool) (bool, error) {
	s := fmt.Sprintf("# Managed by vpsctl - do not edit by hand.\nPort %d\n", port)
	if stageB {
		// EL8's OpenSSH predates KbdInteractiveAuthentication.
		kbd := "ChallengeResponseAuthentication"
		if out, err := m.Effective(); err == nil && len(values(out, "kbdinteractiveauthentication")) > 0 {
			kbd = "KbdInteractiveAuthentication"
		}
		s += "PasswordAuthentication no\n" + kbd + " no\nPubkeyAuthentication yes\nPermitRootLogin no\n"
	}
	p := m.path(DropIn)
	if b, err := os.ReadFile(p); err == nil && string(b) == s {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return false, err
	}
	return true, writeFile(p, []byte(s), 0o644)
}

// validate runs sshd -t and checks the effective port (and, with user != "",
// the hardened auth values, globally and for user via -C to catch Match blocks).
func (m *Manager) validate(port int, user string) error {
	if err := m.run("sshd", "-t"); err != nil {
		return fmt.Errorf("refusing invalid sshd config: %w", err)
	}
	out, err := m.Effective()
	if err != nil {
		return err
	}
	if ports := values(out, "port"); !slices.Equal(ports, []string{strconv.Itoa(port)}) {
		return fmt.Errorf("sshd -T: want only port %d, got %v", port, ports)
	}
	if user == "" {
		return nil
	}
	if err := hardened(out); err != nil {
		return err
	}
	out, err = m.Effective("-C", "user="+user+",host=localhost,addr=127.0.0.1")
	if err != nil {
		return err
	}
	if err := hardened(out); err != nil {
		return fmt.Errorf("for user %s (Match block?): %w", user, err)
	}
	return nil
}

func hardened(out string) error {
	want := map[string]string{"passwordauthentication": "no", "pubkeyauthentication": "yes", "permitrootlogin": "no"}
	for k, v := range want {
		if got := values(out, k); !slices.Equal(got, []string{v}) {
			return fmt.Errorf("effective %s is %v, want %s", k, got, v)
		}
	}
	kbd := append(values(out, "kbdinteractiveauthentication"), values(out, "challengeresponseauthentication")...)
	if len(kbd) == 0 || slices.ContainsFunc(kbd, func(v string) bool { return v != "no" }) {
		return fmt.Errorf("effective keyboard-interactive auth is %v, want no", kbd)
	}
	return nil
}

// scanMatch warns about Match blocks (they can override global auth) and
// about foreign drop-ins.
func (m *Manager) scanMatch() {
	files, _ := filepath.Glob(m.path(DropInDir + "/*.conf"))
	for _, f := range append(files, m.path(MainConfig)) {
		if f != m.path(DropIn) && f != m.path(MainConfig) {
			m.warn("foreign drop-in present: " + strings.TrimPrefix(f, m.Root))
		}
		b, _ := os.ReadFile(f)
		if regexp.MustCompile(`(?mi)^[ \t]*Match[ \t]`).Match(b) {
			m.warn("Match block in " + strings.TrimPrefix(f, m.Root) + " can override global auth settings")
		}
	}
}

// apply restarts sshd (socket or service model) and verifies the listener.
func (m *Manager) apply(port int, portChanged bool) error {
	if portChanged && m.Host.SELinux {
		if err := m.selinuxAllow(port); err != nil {
			return err
		}
	}
	restart := func() error { return m.run("systemctl", "restart", m.Host.SSHUnit) }
	if m.Host.SSHSocket != "" {
		if err := m.run("systemctl", "daemon-reload"); err != nil {
			return err
		}
		if portChanged {
			if err := m.ensureSocketPort(port); err != nil {
				return err
			}
			restart = m.restartSocket
		}
	}
	if err := restart(); err != nil {
		return err
	}
	return m.verifyListener(port)
}

// restartSocket stops the SSH service, then restarts the socket: on Debian 13
// ssh.socket (Accept=no) is not required by ssh.service, so a running sshd
// would keep the old listener (the new port never served, the old one never
// rebindable). Open sessions survive: the units use KillMode=process.
func (m *Manager) restartSocket() error {
	if err := m.run("systemctl", "stop", m.Host.SSHUnit); err != nil {
		return err
	}
	return m.run("systemctl", "restart", m.Host.SSHSocket)
}

// ensureSocketPort writes a manual ListenStream drop-in when the sshd socket
// generator (Ubuntu 24.04+) did not pick up port.
func (m *Manager) ensureSocketPort(port int) error {
	out, err := m.output("systemctl", "cat", m.Host.SSHSocket)
	if err != nil {
		return err
	}
	if regexp.MustCompile(`(?m)^ListenStream=(.*:)?` + strconv.Itoa(port) + `$`).MatchString(out) {
		return nil
	}
	m.warn("socket generator did not emit port " + strconv.Itoa(port) + ": writing manual socket drop-in")
	p := m.path(m.socketDropIn())
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if err := writeFile(p, fmt.Appendf(nil, "[Socket]\nListenStream=\nListenStream=%d\n", port), 0o644); err != nil {
		return err
	}
	return m.run("systemctl", "daemon-reload")
}

// selinuxAllow labels port ssh_port_t so sshd may bind it.
func (m *Manager) selinuxAllow(port int) error {
	if _, err := m.R.Run("semanage", "-h"); err != nil {
		if err := m.Pkgs.Install("policycoreutils-python-utils"); err != nil {
			return err
		}
	}
	p := strconv.Itoa(port)
	if m.run("semanage", "port", "-a", "-t", "ssh_port_t", "-p", "tcp", p) == nil {
		return nil
	}
	return m.run("semanage", "port", "-m", "-t", "ssh_port_t", "-p", "tcp", p)
}

// listening checks port with an exact ss filter (a substring ":22" would
// also match ":2222").
func (m *Manager) listening(port int) bool {
	out, err := m.output("ss", "-ltnH", "sport = :"+strconv.Itoa(port))
	return err == nil && strings.TrimSpace(out) != ""
}

func (m *Manager) verifyListener(port int) error {
	sleep := m.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	for try := range 3 {
		if try > 0 {
			sleep(time.Second)
		}
		if m.listening(port) {
			return nil
		}
	}
	return fmt.Errorf("no sshd listener on port %d after 3 attempts", port)
}

// Effective returns `sshd -T args...` output (e.g. "-C", "user=..."), creating
// host keys and the privsep dir first: sshd -T/-t fail without them before the
// daemon's first start, and systemd removes /run/sshd whenever ssh.service stops.
func (m *Manager) Effective(args ...string) (string, error) {
	if keys, _ := filepath.Glob(m.path("/etc/ssh/ssh_host_*")); len(keys) == 0 {
		if err := m.run("ssh-keygen", "-A"); err != nil {
			return "", err
		}
	}
	if err := os.MkdirAll(m.path("/run/sshd"), 0o755); err != nil {
		return "", err
	}
	return m.output("sshd", append([]string{"-T"}, args...)...)
}

// values returns every value of key in sshd -T output.
func values(out, key string) []string {
	var v []string
	for _, line := range strings.Split(out, "\n") {
		if k, val, ok := strings.Cut(strings.TrimSpace(line), " "); ok && k == key {
			v = append(v, val)
		}
	}
	return v
}

func (m *Manager) run(name string, args ...string) error {
	_, err := m.output(name, args...)
	return err
}

func (m *Manager) output(name string, args ...string) (string, error) {
	res, err := m.R.Run(name, args...)
	if err == nil && res.Code != 0 {
		err = fmt.Errorf("exit %d: %s", res.Code, strings.TrimSpace(res.Stderr))
	}
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return res.Stdout, nil
}

// writeFile replaces p atomically (temp + rename). mode 0 keeps p's mode.
func writeFile(p string, data []byte, mode os.FileMode) error {
	if mode == 0 {
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		mode = fi.Mode().Perm()
	}
	if b, err := os.ReadFile(p); err == nil && bytes.Equal(b, data) {
		return nil
	}
	f, err := os.CreateTemp(filepath.Dir(p), ".vpsctl-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // no-op after rename
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(f.Name(), mode)
	}
	if err == nil {
		err = os.Rename(f.Name(), p)
	}
	return err
}
