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
