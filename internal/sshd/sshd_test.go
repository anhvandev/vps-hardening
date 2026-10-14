package sshd

import (
	"bufio"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anhvandev/vpsctl/internal/firewall"
	"github.com/anhvandev/vpsctl/internal/system"
)

// fakeHost models just enough of sshd/systemd/ss over files under root:
// `sshd -T` evaluates the config, a restart moves the listener to what the
// config (or socket drop-in) says, `ss` reports it. Lines in fail fail once.
type fakeHost struct {
	t         *testing.T
	root      string
	socket    string // socket unit when socket-activated
	listening []int
	fail      map[string]bool
	calls     []string
	restarts  []string // drop-in content at each sshd/socket restart
	stuck     bool     // restarts never move the listener
	// svcHolds: port whose listening fd a running socket-activated ssh.service
	// (Accept=no, no Requires= on the socket: Debian 13) still holds; 0 = not running.
	// A socket restart does not stop that service, so it cannot rebind svcHolds.
	svcHolds int
}

func newFakeHost(t *testing.T) *fakeHost {
	h := &fakeHost{t: t, root: t.TempDir(), listening: []int{22}, fail: map[string]bool{}}
	h.write("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n\nport 22\nUsePAM yes\n")
	h.write("/etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
	h.write("/etc/ssh/ssh_host_ed25519_key", "k")
	return h
}

func (h *fakeHost) write(p, s string) {
	h.t.Helper()
	full := filepath.Join(h.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(s), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fakeHost) read(p string) string {
	b, err := os.ReadFile(filepath.Join(h.root, p))
	if err != nil {
		return "<absent>"
	}
	return string(b)
}

// tree returns every file under root, for byte-exact before/after comparison.
func (h *fakeHost) tree() map[string]string {
	m := map[string]string{}
	filepath.Walk(h.root, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			b, _ := os.ReadFile(p)
			m[strings.TrimPrefix(p, h.root)] = string(b)
		}
		return nil
	})
	return m
}

// effective evaluates the config like sshd: Include'd drop-ins first (sorted),
// Port accumulates, every other keyword is first-match.
func (h *fakeHost) effective() (ports []int, kv map[string]string) {
	kv = map[string]string{}
	files := []string{filepath.Join(h.root, "/etc/ssh/sshd_config")}
	if strings.Contains(h.read("/etc/ssh/sshd_config"), "Include /etc/ssh/sshd_config.d/*.conf") {
		d, _ := filepath.Glob(filepath.Join(h.root, "/etc/ssh/sshd_config.d/*.conf"))
		sort.Strings(d)
		files = append(d, files...)
	}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		sc := bufio.NewScanner(strings.NewReader(string(b)))
		for sc.Scan() {
			fl := strings.Fields(sc.Text())
			if len(fl) < 2 || strings.HasPrefix(fl[0], "#") {
				continue
			}
			k := strings.ToLower(fl[0])
			if k == "match" {
				break
			}
			if k == "port" {
				p, _ := strconv.Atoi(fl[1])
				ports = append(ports, p)
			} else if _, ok := kv[k]; !ok {
				kv[k] = strings.ToLower(fl[1])
			}
		}
	}
	if len(ports) == 0 {
		ports = []int{22}
	}
	for k, v := range map[string]string{
		"passwordauthentication": "yes", "kbdinteractiveauthentication": "yes",
		"pubkeyauthentication": "yes", "permitrootlogin": "prohibit-password",
	} {
		if _, ok := kv[k]; !ok {
			kv[k] = v
		}
	}
	return ports, kv
}

func (h *fakeHost) socketDropIn() string {
	return "/etc/systemd/system/" + h.socket + ".d/99-vpsctl-listen.conf"
}

func (h *fakeHost) Run(name string, args ...string) (system.Result, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	h.calls = append(h.calls, line)
	if h.fail[line] {
		delete(h.fail, line)
		return system.Result{Code: 1, Stderr: "injected failure"}, nil
	}
	switch {
	case name == "sshd" && len(args) > 0 && args[0] == "-T":
		ports, kv := h.effective()
		var out strings.Builder
		for _, p := range ports {
			out.WriteString("port " + strconv.Itoa(p) + "\n")
		}
		for k, v := range kv {
			out.WriteString(k + " " + v + "\n")
		}
		return system.Result{Stdout: out.String()}, nil
	case name == "systemctl" && args[0] == "cat":
		out := "[Socket]\nListenStream=22\n"
		if s := h.read(h.socketDropIn()); s != "<absent>" {
			out += s
		}
		return system.Result{Stdout: out}, nil
	case name == "systemctl" && args[0] == "restart":
		h.restarts = append(h.restarts, h.read("/etc/ssh/sshd_config.d/00-vpsctl.conf"))
		if h.stuck {
			break
		}
		if h.socket != "" {
			h.listening = []int{22}
			for _, l := range strings.Split(h.read(h.socketDropIn()), "\n") {
				if p, err := strconv.Atoi(strings.TrimPrefix(l, "ListenStream=")); err == nil {
					h.listening = []int{p}
				}
			}
			if h.svcHolds != 0 {
				if h.listening[0] == h.svcHolds {
					return system.Result{Code: 1, Stderr: "Address already in use"}, nil
				}
				h.listening = append(h.listening, h.svcHolds)
			}
		} else {
			h.listening, _ = h.effective()
		}
	case name == "systemctl" && args[0] == "stop" && args[1] == "ssh":
		h.svcHolds = 0
	case name == "ss":
		p, _ := strconv.Atoi(strings.TrimPrefix(args[len(args)-1], "sport = :"))
		if slices.Contains(h.listening, p) {
			return system.Result{Stdout: "LISTEN 0 128 0.0.0.0:" + strconv.Itoa(p) + " 0.0.0.0:*\n"}, nil
		}
	}
	return system.Result{}, nil
}

// fakeFW is an in-memory firewall; history holds the rules after every change.
type fakeFW struct {
	rules      []firewall.Rule
	failAllow  bool
	failRemove bool
	history    [][]firewall.Rule
}

func (f *fakeFW) Ensure(int) error               { return nil }
func (f *fakeFW) List() ([]firewall.Rule, error) { return slices.Clone(f.rules), nil }
func (f *fakeFW) Allow(r firewall.Rule) error {
	if f.failAllow {
		f.failAllow = false
		return os.ErrPermission
	}
	if !slices.Contains(f.rules, r) {
		f.rules = append(f.rules, r)
	}
	f.history = append(f.history, slices.Clone(f.rules))
	return nil
}
func (f *fakeFW) Remove(r firewall.Rule) error {
	if f.failRemove {
		f.failRemove = false
		return os.ErrPermission
	}
	f.rules = slices.DeleteFunc(f.rules, func(x firewall.Rule) bool { return x == r })
	f.history = append(f.history, slices.Clone(f.rules))
	return nil
}

func newFW() *fakeFW { return &fakeFW{rules: []firewall.Rule{tcp(22), tcp(80), tcp(443)}} }

func manager(h *fakeHost) *Manager {
	return &Manager{
		R:     h,
		Host:  system.Host{Family: "debian", SSHUnit: "ssh", SSHSocket: h.socket},
		Root:  h.root,
		Sleep: func(time.Duration) {},
	}
}

const stageB22 = "# Managed by vpsctl - do not edit by hand.\nPort 22\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nPermitRootLogin no\n"

// Bash bug 3: a port change on an already-hardened host rewrote the drop-in
// with Port only, re-enabling password auth.
func TestPortChangeOnHardenedHostNeverDowngradesAuth(t *testing.T) {
	h := newFakeHost(t)
	h.write(DropIn, stageB22)
	c, err := manager(h).Begin(newFW(), 2222, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.StageA(); err != nil {
		t.Fatal(err)
	}
	got := h.read(DropIn)
	if !strings.Contains(got, "Port 2222\n") || !strings.Contains(got, "PasswordAuthentication no\n") {
		t.Fatalf("drop-in after port change:\n%s", got)
	}
	if len(h.restarts) == 0 {
		t.Fatal("port change not applied")
	}
	for _, r := range h.restarts {
		if !strings.Contains(r, "PasswordAuthentication no\n") {
			t.Fatalf("sshd restarted with downgraded drop-in:\n%s", r)
		}
	}
}

// Bash bug 4: only the sshd-apply failure rolled back. Every failure after the
// first mutation must restore files, sshd and the firewall to the snapshot.
func TestAnyFailureAfterMutationRestoresSnapshot(t *testing.T) {
	cases := map[string]struct {
		setup  func(h *fakeHost, fw *fakeFW)
		stageB bool // fail in StageB (StageA succeeds first)
	}{
		"stage A sshd -t":         {setup: func(h *fakeHost, _ *fakeFW) { h.fail["sshd -t"] = true }},
		"stage A firewall allow":  {setup: func(_ *fakeHost, fw *fakeFW) { fw.failAllow = true }},
		"stage A restart":         {setup: func(h *fakeHost, _ *fakeFW) { h.fail["systemctl restart ssh"] = true }},
		"stage A no listener":     {setup: func(h *fakeHost, _ *fakeFW) { h.stuck = true }},
		"stage B auth for user":   {stageB: true, setup: func(h *fakeHost, _ *fakeFW) { h.fail["sshd -T -C user=alice,host=localhost,addr=127.0.0.1"] = true }},
		"stage B restart":         {stageB: true, setup: func(h *fakeHost, _ *fakeFW) { h.fail["systemctl restart ssh"] = true }},
		"stage B firewall remove": {stageB: true, setup: func(_ *fakeHost, fw *fakeFW) { fw.failRemove = true }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h, fw := newFakeHost(t), newFW()
			before, rulesBefore := h.tree(), slices.Clone(fw.rules)
			c, err := manager(h).Begin(fw, 2222, "alice")
			if err != nil {
				t.Fatal(err)
			}
			if tc.stageB {
				if err := c.StageA(); err != nil {
					t.Fatal(err)
				}
			}
			tc.setup(h, fw)
			if tc.stageB {
				err = c.StageB()
			} else {
				err = c.StageA()
			}
			if err == nil {
				t.Fatal("want error")
			}
			assertRestored(t, h, fw, before, rulesBefore)
		})
	}
}

// The orchestrator's own failures between stages (e.g. pre-lock assertions)
// roll back through Restore, including after a fully applied Stage B.
func TestRestoreAfterStageBReturnsToSnapshot(t *testing.T) {
	h, fw := newFakeHost(t), newFW()
	before, rulesBefore := h.tree(), slices.Clone(fw.rules)
	c, err := manager(h).Begin(fw, 2222, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.StageA(); err != nil {
		t.Fatal(err)
	}
	if err := c.StageB(); err != nil {
		t.Fatal(err)
	}
	if err := c.Restore(); err != nil {
		t.Fatal(err)
	}
	assertRestored(t, h, fw, before, rulesBefore)
}

// Bash bug 1: rollback left zero SSH ports allowed. Restore re-allows the
// pre-run port first and keeps the new one while sshd is not back on the old.
func TestRollbackNeverLeavesZeroSSHPortsAllowed(t *testing.T) {
	cases := map[string]func(h *fakeHost, fw *fakeFW){
		"clean":                   func(*fakeHost, *fakeFW) {},
		"sshd restart fails":      func(h *fakeHost, _ *fakeFW) { h.fail["systemctl restart ssh"] = true },
		"old port re-allow fails": func(_ *fakeHost, fw *fakeFW) { fw.failAllow = true },
		"sshd stuck on new port":  func(h *fakeHost, _ *fakeFW) { h.stuck = true },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			h, fw := newFakeHost(t), newFW()
			c, err := manager(h).Begin(fw, 2222, "alice")
			if err != nil {
				t.Fatal(err)
			}
			if err := c.StageA(); err != nil {
				t.Fatal(err)
			}
			if err := c.StageB(); err != nil { // closes 22
				t.Fatal(err)
			}
			setup(h, fw)
			restoreErr := c.Restore()
			for _, rules := range fw.history {
				if !slices.Contains(rules, tcp(22)) && !slices.Contains(rules, tcp(2222)) {
					t.Fatalf("zero SSH ports allowed at some point: %v", fw.history)
				}
			}
			if slices.Contains(h.listening, 22) && !slices.Contains(fw.rules, tcp(22)) {
				t.Fatalf("sshd back on 22 but 22 not allowed: %v", fw.rules)
			}
			if !slices.Contains(h.listening, 22) && !slices.Contains(fw.rules, tcp(2222)) {
				t.Fatalf("sshd still on %v but 2222 removed: %v", h.listening, fw.rules)
			}
			if name == "clean" && restoreErr != nil {
				t.Fatal(restoreErr)
			}
		})
	}
}

// Bash bug 2: closing the old SSH port must remove exactly that rule.
func TestStageBClosesOnlyTheOldSSHPort(t *testing.T) {
	h, fw := newFakeHost(t), newFW()
	fw.rules = append(fw.rules, firewall.Rule{Port: 22, Proto: "tcp", From: "203.0.113.0/24"})
	c, err := manager(h).Begin(fw, 2222, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.StageA(); err != nil {
		t.Fatal(err)
	}
	if err := c.StageB(); err != nil {
		t.Fatal(err)
	}
	want := []firewall.Rule{tcp(80), tcp(443), {Port: 22, Proto: "tcp", From: "203.0.113.0/24"}, tcp(2222)}
	if !sameRules(fw.rules, want) {
		t.Fatalf("rules %v, want %v", fw.rules, want)
	}
	if !slices.Equal(h.listening, []int{2222}) {
		t.Fatalf("listening %v", h.listening)
	}
}

// Socket model: when the generator did not emit the new port, a manual
// ListenStream drop-in goes into THIS host's socket unit dir and the socket
// is restarted. Never `systemctl reload`.
func TestSocketModelPortChangeWritesSocketDropInAndNeverReloads(t *testing.T) {
	h := newFakeHost(t)
	h.socket = "sshd.socket"
	fw := newFW()
	c, err := manager(h).Begin(fw, 2222, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.StageA(); err != nil {
		t.Fatal(err)
	}
	if got := h.read("/etc/systemd/system/sshd.socket.d/99-vpsctl-listen.conf"); got != "[Socket]\nListenStream=\nListenStream=2222\n" {
		t.Fatalf("socket drop-in = %q", got)
	}
	if !slices.Contains(h.calls, "systemctl restart sshd.socket") || !slices.Equal(h.listening, []int{2222}) {
		t.Fatalf("socket not restarted onto 2222: %q", h.calls)
	}
	if err := c.Restore(); err != nil {
		t.Fatal(err)
	}
	if h.read("/etc/systemd/system/sshd.socket.d/99-vpsctl-listen.conf") != "<absent>" || !slices.Equal(h.listening, []int{22}) {
		t.Fatalf("socket drop-in not rolled back, listening %v", h.listening)
	}
	for _, call := range h.calls {
		if strings.Contains(call, "reload") && call != "systemctl daemon-reload" {
			t.Fatalf("used reload: %q", call)
		}
	}
}

// Debian 13: ssh.socket (Accept=no) does not stop a running ssh.service on
// restart, so that sshd keeps the old listener. The service must be stopped
// first, or the new port is never served and a rollback cannot rebind the old one.
func TestSocketRestartStopsRunningServiceSoPortMovesAndRollsBack(t *testing.T) {
	h := newFakeHost(t)
	h.socket = "ssh.socket"
	h.svcHolds = 22 // someone logged in: ssh.service is running
	c, err := manager(h).Begin(newFW(), 2222, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.StageA(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(h.listening, []int{2222}) {
		t.Fatalf("after StageA listening %v, want only 2222", h.listening)
	}
	h.svcHolds = 2222 // a login on the new port starts ssh.service again
	if err := c.Restore(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(h.listening, []int{22}) {
		t.Fatalf("after Restore listening %v, want only 22", h.listening)
	}
}

func TestStageAPrependsMissingIncludeAndLabelsSELinuxPort(t *testing.T) {
	h := newFakeHost(t)
	h.write("/etc/ssh/sshd_config", "Port 22\n")
	m := manager(h)
	m.Host.SELinux = true
	c, err := m.Begin(nil, 2222, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.StageA(); err != nil {
		t.Fatal(err)
	}
	if got := h.read("/etc/ssh/sshd_config"); !strings.HasPrefix(got, "Include /etc/ssh/sshd_config.d/*.conf\n") {
		t.Fatalf("sshd_config = %q", got)
	}
	label, restart := slices.Index(h.calls, "semanage port -a -t ssh_port_t -p tcp 2222"), slices.Index(h.calls, "systemctl restart ssh")
	if label < 0 || label > restart {
		t.Fatalf("want ssh_port_t label before restart: %q", h.calls)
	}
}

func assertRestored(t *testing.T, h *fakeHost, fw *fakeFW, before map[string]string, rules []firewall.Rule) {
	t.Helper()
	after := h.tree()
	for p, s := range before {
		if after[p] != s {
			t.Errorf("%s not restored:\n got %q\nwant %q", p, after[p], s)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			t.Errorf("%s left behind", p)
		}
	}
	if !slices.Equal(h.listening, []int{22}) {
		t.Errorf("sshd listening on %v, want [22]", h.listening)
	}
	if !sameRules(fw.rules, rules) {
		t.Errorf("firewall %v, want %v", fw.rules, rules)
	}
}

func sameRules(a, b []firewall.Rule) bool {
	return len(a) == len(b) && !slices.ContainsFunc(a, func(r firewall.Rule) bool { return !slices.Contains(b, r) })
}

// EL ships sshd_config 0600: prepending the Include must keep its mode.
func TestEnsureIncludeKeepsMainConfigMode(t *testing.T) {
	h := newFakeHost(t)
	h.write("/etc/ssh/sshd_config", "Port 22\n")
	p := filepath.Join(h.root, "/etc/ssh/sshd_config")
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := manager(h).ensureInclude(); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("sshd_config mode %o, want 600", fi.Mode().Perm())
	}
}
