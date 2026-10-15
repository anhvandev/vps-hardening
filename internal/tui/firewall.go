package tui

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/firewall"
	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

func init() { screens["Firewall"] = newFirewall }

// firewallScreen lists every Firewall Rule read live from ufw/firewalld (rules
// added by hand included), each marked with whether a Listening Port backs it.
type firewallScreen struct {
	m      *harden.Machine
	loaded bool
	fw     firewallMsg
}

type firewallMsg struct {
	state     string
	rules     []firewall.Rule
	err       error      // rules not listed
	listeners []listener // nil if ss failed
}

// listener is a Listening Port: a tcp socket in LISTEN or a bound udp socket.
type listener struct {
	proto string
	port  int
}

func newFirewall(m *harden.Machine) tea.Model { return firewallScreen{m: m} }

func (f firewallScreen) Init() tea.Cmd {
	return func() tea.Msg {
		var msg firewallMsg
		msg.state, msg.rules, msg.err = firewallRules(f.m)
		msg.listeners = listeners(f.m.R)
		return msg
	}
}

func (f firewallScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case firewallMsg:
		f.fw, f.loaded = msg, true
	case tea.KeyPressMsg:
		if msg.String() == "esc" {
			return f, Back
		}
	}
	return f, nil
}

func (f firewallScreen) View() tea.View {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Firewall") + "\n\n")
	if !f.loaded {
		return tea.NewView(b.String() + "loading…")
	}
	name := map[string]string{"debian": "ufw ", "rhel": "firewalld "}[f.m.Host.Family]
	b.WriteString(name + f.fw.state + "\n\n")
	switch {
	case f.fw.err != nil && f.fw.state == "active":
		b.WriteString("rules unreadable: " + f.fw.err.Error())
	case f.fw.err != nil:
	case len(f.fw.rules) == 0:
		b.WriteString("no rules")
	default:
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "Port\tProto\tSource\tListening")
		for _, r := range f.fw.rules {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", ports(r), or(r.Proto, "any"), or(r.From, "anywhere"), f.backed(r))
		}
		tw.Flush()
	}
	return tea.NewView(strings.TrimRight(b.String(), "\n"))
}

// backed says whether a listener matches r's protocol inside its port range.
func (f firewallScreen) backed(r firewall.Rule) string {
	if f.fw.listeners == nil {
		return "unknown"
	}
	end := max(r.End, r.Port)
	if slices.ContainsFunc(f.fw.listeners, func(l listener) bool {
		return (r.Proto == "" || r.Proto == l.proto) && l.port >= r.Port && l.port <= end
	}) {
		return "yes"
	}
	return "no"
}

func ports(r firewall.Rule) string {
	s := strconv.Itoa(r.Port)
	if r.End != 0 {
		s += fmt.Sprintf("-%d", r.End)
	}
	if r.Limit {
		s += " (rate-limited)"
	}
	return s
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// listeners reads `ss -Hltun` (no header, listening tcp+udp, numeric):
// "Netid State Recv-Q Send-Q Local:Port Peer:Port". nil if ss failed.
func listeners(r system.Runner) []listener {
	res, err := r.Run("ss", "-Hltun")
	if err != nil || res.Code != 0 {
		return nil
	}
	ls := []listener{}
	for _, line := range strings.Split(res.Stdout, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		local := f[4]
		if port, err := strconv.Atoi(local[strings.LastIndex(local, ":")+1:]); err == nil {
			ls = append(ls, listener{f[0], port})
		}
	}
	return ls
}
