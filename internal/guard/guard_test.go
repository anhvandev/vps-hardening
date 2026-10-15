package guard

import (
	"testing"

	"github.com/anhvandev/vpsctl/internal/firewall"
)

var (
	ssh      = firewall.Rule{Port: 22, Proto: "tcp"}
	web      = firewall.Rule{Port: 80, Proto: "tcp"}
	sshFrom  = firewall.Rule{Port: 22, Proto: "tcp", From: "10.0.0.0/8"}
	sshRange = firewall.Rule{Port: 1, End: 1024, Proto: "tcp"}
)

func TestRemoveRuleKeepsSSHPortOpen(t *testing.T) {
	for _, tc := range []struct {
		name   string
		facts  Facts
		remove firewall.Rule
		refuse bool
	}{
		{"unrelated rule", Facts{SSHPort: 22, Rules: []firewall.Rule{ssh, web}}, web, false},
		{"the SSH rule", Facts{SSHPort: 22, Rules: []firewall.Rule{ssh, web}}, ssh, true},
		{"SSH rule on a custom port", Facts{SSHPort: 2222, Rules: []firewall.Rule{{Port: 2222, Proto: "tcp"}, ssh}}, firewall.Rule{Port: 2222, Proto: "tcp"}, true},
		{"old SSH port once moved", Facts{SSHPort: 2222, Rules: []firewall.Rule{{Port: 2222, Proto: "tcp"}, ssh}}, ssh, false},
		{"proto-less rule allowing SSH", Facts{SSHPort: 22, Rules: []firewall.Rule{{Port: 22}}}, firewall.Rule{Port: 22}, true},
		{"rate-limited SSH rule", Facts{SSHPort: 22, Rules: []firewall.Rule{{Port: 22, Proto: "tcp", Limit: true}}}, firewall.Rule{Port: 22, Proto: "tcp", Limit: true}, true},
		{"range covering SSH", Facts{SSHPort: 22, Rules: []firewall.Rule{sshRange}}, sshRange, true},
		{"udp rule on the SSH port", Facts{SSHPort: 22, Rules: []firewall.Rule{ssh, {Port: 22, Proto: "udp"}}}, firewall.Rule{Port: 22, Proto: "udp"}, false},
		{"SSH rule while a range still allows it", Facts{SSHPort: 22, Rules: []firewall.Rule{ssh, sshRange}}, ssh, false},
		{"source-limited SSH rule while open to anywhere", Facts{SSHPort: 22, Rules: []firewall.Rule{ssh, sshFrom}}, sshFrom, false},
		{"anywhere SSH rule leaving only a source-limited one", Facts{SSHPort: 22, Rules: []firewall.Rule{ssh, sshFrom}}, ssh, true},
		{"only SSH rule, source-limited", Facts{SSHPort: 22, Rules: []firewall.Rule{sshFrom}}, sshFrom, true},
		{"any rule while the SSH port is unknown", Facts{Rules: []firewall.Rule{ssh, web}}, web, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Check(tc.facts, RemoveRule{tc.remove})
			if refused := err != nil; refused != tc.refuse {
				t.Errorf("refused = %v (%v), want %v", refused, err, tc.refuse)
			}
		})
	}
}

func TestRefusalNamesTheSSHPort(t *testing.T) {
	err := Check(Facts{SSHPort: 2222, Rules: []firewall.Rule{{Port: 2222, Proto: "tcp"}}}, RemoveRule{firewall.Rule{Port: 2222, Proto: "tcp"}})
	if err == nil || err.Error() != "refused: SSH port 2222 would no longer be open to anywhere" {
		t.Errorf("err = %v", err)
	}
}

func TestChangeSSHPortRefusesAnotherListeningPort(t *testing.T) {
	facts := Facts{SSHPort: 22, Listening: []int{22, 5432}}
	for port, refuse := range map[int]bool{2222: false, 5432: true} {
		err := Check(facts, ChangeSSHPort{port})
		if refused := err != nil; refused != refuse {
			t.Errorf("port %d: refused = %v (%v), want %v", port, refused, err, refuse)
		}
	}
	if err := Check(facts, ChangeSSHPort{5432}); err == nil || err.Error() != "refused: port 5432 is already a Listening Port" {
		t.Errorf("err = %v", err)
	}
}

func TestProtectedUnits(t *testing.T) {
	for _, tc := range []struct {
		unit, verb string
		refuse     bool
	}{
		{"ssh.service", "stop", true},
		{"ssh", "disable", true},
		{"sshd.service", "stop", true},
		{"ssh.socket", "stop", true},
		{"sshd.socket", "disable", true},
		{"ssh.service", "restart", true},
		{"sshd.socket", "restart", true},
		{"ssh.service", "start", false},
		{"ssh.service", "enable", false},
		{"ufw.service", "stop", true},
		{"ufw.service", "restart", false},
		{"firewalld.service", "disable", true},
		{"networking.service", "stop", true},
		{"systemd-networkd.service", "stop", true},
		{"NetworkManager.service", "disable", true},
		{"systemd-resolved.service", "stop", true},
		{"cloud-init.service", "disable", true},
		{"cloud-final.service", "stop", true},
		{"fail2ban.service", "stop", false},
		{"fail2ban", "start", false},
		{"nginx.service", "stop", false},
		{"nginx.service", "disable", false},
	} {
		t.Run(tc.unit+" "+tc.verb, func(t *testing.T) {
			err := Check(Facts{}, UnitAction{Unit: tc.unit, Verb: tc.verb})
			if refused := err != nil; refused != tc.refuse {
				t.Errorf("refused = %v (%v), want %v", refused, err, tc.refuse)
			}
		})
	}
}

func TestProtectedUnitRefusalGivesReason(t *testing.T) {
	err := Check(Facts{}, UnitAction{Unit: "ssh.service", Verb: "stop"})
	if err == nil || err.Error() != "refused: ssh.service is a Protected Unit (remote SSH access), cannot stop it" {
		t.Errorf("err = %v", err)
	}
}
