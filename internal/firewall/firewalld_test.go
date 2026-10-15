package firewall

import (
	"slices"
	"strings"
	"testing"

	"github.com/anhvandev/vpsctl/internal/system"
)

func TestFirewalldEnsureInstallsAndAllowsSSHPortBeforeStarting(t *testing.T) {
	b, f := backend(t, "rhel", map[string]system.Result{
		"dnf install -y firewalld":                 {},
		"systemctl is-active firewalld":            {Code: 3, Stdout: "inactive\n"},
		"firewall-offline-cmd --add-port=2222/tcp": {},
		"systemctl enable --now firewalld":         {},
	})
	if err := b.Ensure(2222); err != nil {
		t.Fatalf("%v (calls %q)", err, f.Calls)
	}
	allow, enable := index(f.Calls, "firewall-offline-cmd --add-port=2222/tcp"), index(f.Calls, "systemctl enable --now firewalld")
	if index(f.Calls, "dnf install -y firewalld") < 0 || allow < 0 || enable < 0 || allow > enable {
		t.Fatalf("want install, then allow 2222/tcp before enable; calls: %q", f.Calls)
	}
}

func TestFirewalldEnsureWhenActiveAllowsAndReloads(t *testing.T) {
	b, f := backend(t, "rhel", map[string]system.Result{
		"firewall-cmd --version":                     {Stdout: "1.3.4\n"},
		"systemctl is-active firewalld":              {Stdout: "active\n"},
		"firewall-cmd --permanent --add-port=22/tcp": {},
		"firewall-cmd --reload":                      {},
	})
	if err := b.Ensure(22); err != nil {
		t.Fatalf("%v (calls %q)", err, f.Calls)
	}
}

var firewalldState = map[string]system.Result{
	"firewall-cmd --permanent --list-ports":    {Stdout: "2222/tcp 80/tcp 6000-6100/udp\n"},
	"firewall-cmd --permanent --list-services": {Stdout: "cockpit dhcpv6-client ssh\n"},
	"firewall-cmd --permanent --list-rich-rules": {Stdout: `rule family="ipv4" source address="203.0.113.0/24" port port="22" protocol="tcp" accept
rule family="ipv4" source address="10.0.0.5" forward-port port="80" protocol="tcp" to-port="8080"
`},
}

func TestFirewalldListMapsSSHServiceAndRichRules(t *testing.T) {
	b, _ := backend(t, "rhel", firewalldState)
	got, err := b.List()
	if err != nil {
		t.Fatal(err)
	}
	want := []Rule{
		{Port: 2222, Proto: "tcp"},
		{Port: 80, Proto: "tcp"},
		{Port: 6000, End: 6100, Proto: "udp"},
		{Port: 22, Proto: "tcp"},
		{Port: 22, Proto: "tcp", From: "203.0.113.0/24"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}

func mutations(calls []string) []string {
	var m []string
	for _, c := range calls {
		if strings.Contains(c, "--add-") || strings.Contains(c, "--remove-") {
			m = append(m, c)
		}
	}
	return m
}

// Closing old SSH port 22 must also drop the `ssh` service (which opens 22),
// and nothing else.
func TestFirewalldRemoveSSHPortDropsOnlyPort22(t *testing.T) {
	b, f := backend(t, "rhel", map[string]system.Result{
		"firewall-cmd --permanent --remove-port=22/tcp": {},
		"firewall-cmd --permanent --remove-service=ssh": {},
		"firewall-cmd --reload":                         {},
	})
	if err := b.Remove(Rule{Port: 22, Proto: "tcp"}); err != nil {
		t.Fatalf("%v (calls %q)", err, f.Calls)
	}
	want := []string{"firewall-cmd --permanent --remove-port=22/tcp", "firewall-cmd --permanent --remove-service=ssh"}
	if !slices.Equal(mutations(f.Calls), want) {
		t.Fatalf("mutations: %q", mutations(f.Calls))
	}
}

func TestFirewalldSourceRuleIsRichRule(t *testing.T) {
	rich := `rule family="ipv4" source address="203.0.113.0/24" port port="22" protocol="tcp" accept`
	b, f := backend(t, "rhel", map[string]system.Result{
		"firewall-cmd --permanent --add-rich-rule=" + rich:    {},
		"firewall-cmd --permanent --remove-rich-rule=" + rich: {},
		"firewall-cmd --permanent --add-port=6000-6100/udp":   {},
		"firewall-cmd --reload":                               {},
	})
	r := Rule{Port: 22, Proto: "tcp", From: "203.0.113.0/24"}
	for _, err := range []error{b.Allow(r), b.Remove(r), b.Allow(Rule{Port: 6000, End: 6100, Proto: "udp"})} {
		if err != nil {
			t.Fatalf("%v (calls %q)", err, f.Calls)
		}
	}
	if err := b.Allow(Rule{Port: 53}); err == nil {
		t.Fatal("firewalld needs an explicit protocol")
	}
}
