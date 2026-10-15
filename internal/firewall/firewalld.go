package firewall

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/anhvandev/vpsctl/internal/system"
)

// sshRule is what firewalld's stock `ssh` service opens.
// ponytail: only the ssh service is mapped to a rule; other services are not
// Firewall Rules (not listed, never touched). Map more if the TUI needs them.
var sshRule = Rule{Port: 22, Proto: "tcp"}

var richRe = regexp.MustCompile(`^rule family="ipv[46]" source address="([^"]+)" port port="([^"]+)" protocol="(tcp|udp)" accept$`)

type firewalld struct {
	r system.Runner
	p *system.Packages
}

func (fw *firewalld) Ensure(sshPort int) error {
	if _, err := fw.r.Run("firewall-cmd", "--version"); err != nil {
		if err := fw.p.Install("firewalld"); err != nil {
			return err
		}
	}
	port := fmt.Sprintf("--add-port=%d/tcp", sshPort)
	if res, err := fw.r.Run("systemctl", "is-active", "firewalld"); err == nil && res.Code == 0 {
		return fw.permanent(port)
	}
	// Not running: write the rule offline BEFORE starting, so the first start
	// never cuts the live session.
	if _, err := run(fw.r, "firewall-offline-cmd", port); err != nil {
		return err
	}
	_, err := run(fw.r, "systemctl", "enable", "--now", "firewalld")
	return err
}

// List reads the permanent config: plain ports, the ssh service (as 22/tcp)
// and source-limited accept rich rules. Other rich rules are skipped.
func (fw *firewalld) List() ([]Rule, error) {
	var rules []Rule
	ports, err := run(fw.r, "firewall-cmd", "--permanent", "--list-ports")
	if err != nil {
		return nil, err
	}
	for _, p := range strings.Fields(ports) {
		spec, proto, _ := strings.Cut(p, "/")
		if port, end, ok := parsePorts(spec, "-"); ok {
			rules = append(rules, Rule{Port: port, End: end, Proto: proto})
		}
	}
	services, err := run(fw.r, "firewall-cmd", "--permanent", "--list-services")
	if err != nil {
		return nil, err
	}
	if slices.Contains(strings.Fields(services), "ssh") && !slices.Contains(rules, sshRule) {
		rules = append(rules, sshRule)
	}
	rich, err := run(fw.r, "firewall-cmd", "--permanent", "--list-rich-rules")
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(rich, "\n") {
		m := richRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		if port, end, ok := parsePorts(m[2], "-"); ok {
			rules = append(rules, Rule{Port: port, End: end, Proto: m[3], From: m[1]})
		}
	}
	return rules, nil
}

func (fw *firewalld) Allow(r Rule) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if r.Proto == "" {
		return errors.New("firewalld: protocol (tcp/udp) is required")
	}
	return fw.permanent(fwArg("add", r))
}

// Remove deletes exactly r. Removing 22/tcp also drops the ssh service,
// which is how firewalld opens 22 by default.
func (fw *firewalld) Remove(r Rule) error {
	args := []string{fwArg("remove", r)}
	if r == sshRule {
		args = append(args, "--remove-service=ssh")
	}
	return fw.permanent(args...)
}

// permanent applies each change to the permanent config, then reloads.
func (fw *firewalld) permanent(changes ...string) error {
	for _, c := range changes {
		if _, err := run(fw.r, "firewall-cmd", "--permanent", c); err != nil {
			return err
		}
	}
	_, err := run(fw.r, "firewall-cmd", "--reload")
	return err
}

// fwArg builds --add-port=/--remove-port= or the rich-rule form for a source.
func fwArg(op string, r Rule) string {
	if r.From == "" {
		return fmt.Sprintf("--%s-port=%s/%s", op, r.ports("-"), r.Proto)
	}
	family := "ipv4"
	if strings.Contains(r.From, ":") {
		family = "ipv6"
	}
	return fmt.Sprintf(`--%s-rich-rule=rule family="%s" source address="%s" port port="%s" protocol="%s" accept`,
		op, family, r.From, r.ports("-"), r.Proto)
}
