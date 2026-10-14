package firewall

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/anhvandev/vpsctl/internal/system"
)

type ufw struct {
	r system.Runner
	p *system.Packages
}

func (u *ufw) Ensure(sshPort int) error {
	if _, err := u.r.Run("ufw", "version"); err != nil {
		if err := u.p.Install("ufw"); err != nil {
			return err
		}
	}
	// Allow BEFORE enabling: enabling first can cut the live session.
	if _, err := run(u.r, "ufw", "allow", fmt.Sprintf("%d/tcp", sshPort)); err != nil {
		return err
	}
	out, err := run(u.r, "ufw", "status")
	if err != nil {
		return err
	}
	if strings.Contains(out, "Status: active") {
		return nil
	}
	_, err = run(u.r, "ufw", "--force", "enable")
	return err
}

// List reads `ufw show added`, which (unlike `ufw status`) also works while
// ufw is inactive and prints each rule once (no v6 duplicates). Incoming
// allow and limit rules are Firewall Rules; the OpenSSH app profile is listed
// as 22/tcp (like firewalld's ssh service); other app profiles and interface
// rules are skipped.
func (u *ufw) List() ([]Rule, error) {
	out, err := run(u.r, "ufw", "show", "added")
	if err != nil {
		return nil, err
	}
	var rules []Rule
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if i := slices.Index(f, "comment"); i >= 0 {
			f = f[:i]
		}
		if len(f) < 3 || f[0] != "ufw" || (f[1] != "allow" && f[1] != "limit") {
			continue
		}
		r := Rule{Limit: f[1] == "limit"}
		var spec string
		switch f = f[2:]; {
		case !r.Limit && len(f) == 1 && f[0] == "OpenSSH":
			if !slices.Contains(rules, sshRule) {
				rules = append(rules, sshRule)
			}
			continue
		case len(f) == 1:
			spec, r.Proto, _ = strings.Cut(f[0], "/")
		case len(f) >= 6 && f[0] == "from" && f[2] == "to" && f[3] == "any" && f[4] == "port":
			r.From, spec = f[1], f[5]
			if len(f) == 8 && f[6] == "proto" {
				r.Proto = f[7]
			} else if len(f) != 6 {
				continue
			}
		default:
			continue
		}
		var ok bool
		if r.Port, r.End, ok = parsePorts(spec, ":"); ok {
			rules = append(rules, r)
		}
	}
	return rules, nil
}

func (u *ufw) Allow(r Rule) error {
	if err := r.validate(); err != nil {
		return err
	}
	_, err := run(u.r, "ufw", ufwArgs(r)...)
	return err
}

// Remove deletes exactly r (both v4 and v6 copies, as ufw does). Removing
// 22/tcp also drops the OpenSSH app profile, which List shows as 22/tcp.
func (u *ufw) Remove(r Rule) error {
	if _, err := run(u.r, "ufw", append([]string{"delete"}, ufwArgs(r)...)...); err != nil {
		return err
	}
	if r != sshRule {
		return nil
	}
	out, err := run(u.r, "ufw", "show", "added")
	if err != nil || !regexp.MustCompile(`(?m)^ufw allow OpenSSH\s*$`).MatchString(out) {
		return err
	}
	_, err = run(u.r, "ufw", "delete", "allow", "OpenSSH")
	return err
}

// ufwArgs is the rule part of a ufw command, starting with allow/limit.
func ufwArgs(r Rule) []string {
	verb := "allow"
	if r.Limit {
		verb = "limit"
	}
	if r.From == "" {
		spec := r.ports(":")
		if r.Proto != "" {
			spec += "/" + r.Proto
		}
		return []string{verb, spec}
	}
	args := []string{verb, "from", r.From, "to", "any", "port", r.ports(":")}
	if r.Proto != "" {
		args = append(args, "proto", r.Proto)
	}
	return args
}
