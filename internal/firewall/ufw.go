package firewall

import (
	"fmt"
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
// ufw is inactive and prints each rule once (no v6 duplicates). Only plain
// incoming allow rules are Firewall Rules; app profiles, limit and
// interface rules are skipped.
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
		if len(f) < 3 || f[0] != "ufw" || f[1] != "allow" {
			continue
		}
		var r Rule
		var spec string
		switch f = f[2:]; {
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
	_, err := run(u.r, "ufw", append([]string{"allow"}, ufwArgs(r)...)...)
	return err
}

// Remove deletes exactly r (both v4 and v6 copies, as ufw does).
func (u *ufw) Remove(r Rule) error {
	_, err := run(u.r, "ufw", append([]string{"delete", "allow"}, ufwArgs(r)...)...)
	return err
}

func ufwArgs(r Rule) []string {
	if r.From == "" {
		spec := r.ports(":")
		if r.Proto != "" {
			spec += "/" + r.Proto
		}
		return []string{spec}
	}
	args := []string{"from", r.From, "to", "any", "port", r.ports(":")}
	if r.Proto != "" {
		args = append(args, "proto", r.Proto)
	}
	return args
}
