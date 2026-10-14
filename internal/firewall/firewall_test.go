package firewall

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/anhvandev/vpsctl/internal/system"
)

func backend(t *testing.T, family string, results map[string]system.Result) (Backend, *system.Fake) {
	t.Helper()
	f := &system.Fake{Results: results}
	pm := map[string]string{"debian": "apt", "rhel": "dnf"}[family]
	b, err := New(system.Host{Family: family, PkgManager: pm}, f, &system.Packages{R: f, Manager: pm})
	if err != nil {
		t.Fatal(err)
	}
	return b, f
}

func index(calls []string, line string) int { return slices.Index(calls, line) }

// Bash bug 1: a first ufw enable during a port change only allowed the new
// port, cutting the live session on the old one.
func TestUfwEnsureAllowsCurrentSSHPortBeforeEnabling(t *testing.T) {
	b, f := backend(t, "debian", map[string]system.Result{
		"ufw version":        {},
		"ufw allow 22/tcp":   {},
		"ufw status":         {Stdout: "Status: inactive\n"},
		"ufw --force enable": {},
	})
	if err := b.Ensure(22); err != nil {
		t.Fatal(err)
	}
	allow, enable := index(f.Calls, "ufw allow 22/tcp"), index(f.Calls, "ufw --force enable")
	if allow < 0 || enable < 0 || allow > enable {
		t.Fatalf("want allow 22/tcp before enable, calls: %q", f.Calls)
	}
}

const ufwAdded = `Added user rules (see 'ufw status' for running firewall):
ufw allow 22/tcp
ufw allow 2222/tcp
ufw allow 80/tcp
ufw allow 443/tcp comment 'web'
ufw allow 53
ufw allow 6000:6100/udp
ufw allow from 203.0.113.0/24 to any port 22 proto tcp
ufw allow from 10.0.0.5 to any port 8080
ufw allow OpenSSH
ufw limit 25/tcp
`

func TestUfwListParsesFirewallRules(t *testing.T) {
	b, _ := backend(t, "debian", map[string]system.Result{"ufw show added": {Stdout: ufwAdded}})
	got, err := b.List()
	if err != nil {
		t.Fatal(err)
	}
	want := []Rule{
		{Port: 22, Proto: "tcp"},
		{Port: 2222, Proto: "tcp"},
		{Port: 80, Proto: "tcp"},
		{Port: 443, Proto: "tcp"},
		{Port: 53},
		{Port: 6000, End: 6100, Proto: "udp"},
		{Port: 22, Proto: "tcp", From: "203.0.113.0/24"},
		{Port: 8080, From: "10.0.0.5"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}

// Bash bug 2: closing the old SSH port deleted every numeric tcp allow rule.
func TestUfwRemoveDeletesOnlyThatRule(t *testing.T) {
	b, f := backend(t, "debian", map[string]system.Result{
		"ufw delete allow 22/tcp": {},
	})
	if err := b.Remove(Rule{Port: 22, Proto: "tcp"}); err != nil {
		t.Fatal(err)
	}
	var mutations []string
	for _, c := range f.Calls {
		if strings.HasPrefix(c, "ufw delete") || strings.HasPrefix(c, "ufw allow") {
			mutations = append(mutations, c)
		}
	}
	if !slices.Equal(mutations, []string{"ufw delete allow 22/tcp"}) {
		t.Fatalf("mutations: %q", mutations)
	}
}

func TestUfwAllowAndRemoveCommandForms(t *testing.T) {
	b, f := backend(t, "debian", map[string]system.Result{
		"ufw allow 6000:6100/udp":                                {},
		"ufw allow from 203.0.113.0/24 to any port 22 proto tcp": {},
		"ufw delete allow from 10.0.0.5 to any port 8080":        {},
	})
	for _, err := range []error{
		b.Allow(Rule{Port: 6000, End: 6100, Proto: "udp"}),
		b.Allow(Rule{Port: 22, Proto: "tcp", From: "203.0.113.0/24"}),
		b.Remove(Rule{Port: 8080, From: "10.0.0.5"}),
	} {
		if err != nil {
			t.Fatalf("%v (calls %q)", err, f.Calls)
		}
	}
}

// mem is an in-memory Backend recording mutations, for Restore.
type mem struct {
	rules []Rule
	ops   []string
}

func (m *mem) Ensure(int) error      { return nil }
func (m *mem) List() ([]Rule, error) { return slices.Clone(m.rules), nil }
func (m *mem) Allow(r Rule) error {
	m.ops = append(m.ops, fmt.Sprintf("allow %d", r.Port))
	m.rules = append(m.rules, r)
	return nil
}
func (m *mem) Remove(r Rule) error {
	m.ops = append(m.ops, fmt.Sprintf("remove %d", r.Port))
	m.rules = slices.DeleteFunc(m.rules, func(x Rule) bool { return x == r })
	return nil
}

// Rollback must re-open the pre-run SSH port before closing anything, so
// there is never a moment with zero SSH ports allowed.
func TestRestoreReopensSnapshotRulesBeforeRemovingNewOnes(t *testing.T) {
	snap := []Rule{{Port: 22, Proto: "tcp"}, {Port: 80, Proto: "tcp"}}
	m := &mem{rules: []Rule{{Port: 80, Proto: "tcp"}, {Port: 2222, Proto: "tcp"}}}
	if err := Restore(m, snap); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.ops, []string{"allow 22", "remove 2222"}) {
		t.Fatalf("ops: %q", m.ops)
	}
	if !slices.Equal(m.rules, []Rule{{Port: 80, Proto: "tcp"}, {Port: 22, Proto: "tcp"}}) {
		t.Fatalf("rules: %+v", m.rules)
	}
}

func TestAllowRejectsInvalidRule(t *testing.T) {
	b, f := backend(t, "debian", nil)
	for _, r := range []Rule{
		{Port: 0, Proto: "tcp"},
		{Port: 70000, Proto: "tcp"},
		{Port: 100, End: 50, Proto: "tcp"},
		{Port: 22, Proto: "icmp"},
		{Port: 22, Proto: "tcp", From: `1.2.3.4" accept`},
	} {
		if err := b.Allow(r); err == nil {
			t.Errorf("%+v: expected error", r)
		}
	}
	if len(f.Calls) != 0 {
		t.Fatalf("invalid rules must not reach the host: %q", f.Calls)
	}
}
