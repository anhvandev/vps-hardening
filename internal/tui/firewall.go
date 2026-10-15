package tui

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/anhvandev/vpsctl/internal/firewall"
	"github.com/anhvandev/vpsctl/internal/guard"
	"github.com/anhvandev/vpsctl/internal/harden"
)

func init() { screens["Firewall"] = newFirewall }

var selectedStyle = lipgloss.NewStyle().Reverse(true)

// firewallScreen lists every Firewall Rule read live from ufw/firewalld (rules
// added by hand included), each marked with whether a Listening Port backs it.
// a opens a port or range, d removes the selected rule (Lockout Guard checked).
type firewallScreen struct {
	m      *harden.Machine
	loaded bool
	fw     firewallMsg
	cursor int    // selected rule
	adding bool   // the open-a-port prompt is up
	input  string // what was typed into it
	status string // outcome of the last action, or an input error
}

// changedMsg is the outcome of a mutation, shown inline.
type changedMsg string

type firewallMsg struct {
	state     string
	rules     []firewall.Rule
	err       error           // rules not listed
	listening []listeningPort // nil if ss failed
}

func newFirewall(m *harden.Machine) tea.Model { return firewallScreen{m: m} }

func (f firewallScreen) Init() tea.Cmd {
	return func() tea.Msg {
		var msg firewallMsg
		msg.state, msg.rules, msg.err = firewallRules(f.m)
		msg.listening = listeningPorts(f.m.R)
		return msg
	}
}

func (f firewallScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case firewallMsg:
		f.fw, f.loaded = msg, true
		f.cursor = max(min(f.cursor, len(msg.rules)-1), 0)
	case changedMsg:
		f.status = string(msg)
		return f, f.Init()
	case tea.KeyPressMsg:
		if f.adding {
			return f.promptKey(msg)
		}
		switch msg.String() {
		case "esc":
			return f, Back
		case "up", "k":
			f.cursor = max(f.cursor-1, 0)
		case "down", "j":
			f.cursor = max(min(f.cursor+1, len(f.fw.rules)-1), 0)
		case "a":
			f.adding, f.input, f.status = true, "", ""
		case "d":
			if f.cursor < len(f.fw.rules) {
				return f, f.remove(f.fw.rules[f.cursor])
			}
		}
	}
	return f, nil
}

// promptKey edits the open-a-port prompt; enter validates, then opens.
func (f firewallScreen) promptKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		f.adding, f.status = false, ""
	case "backspace":
		f.input = dropLast(f.input)
	case "enter":
		r, err := parseRule(f.input)
		if err != nil {
			f.status = err.Error()
			return f, nil
		}
		f.adding, f.status = false, ""
		return f, f.change("firewall open "+r.String(), "opened "+r.String(), func(fw firewall.Backend) error {
			return fw.Allow(r)
		})
	default:
		f.input += msg.Text
	}
	return f, nil
}

// remove deletes exactly r unless the Lockout Guard refuses, deciding on the
// SSH port and rules read under the lock.
func (f firewallScreen) remove(r firewall.Rule) tea.Cmd {
	return f.change("firewall remove "+r.String(), "removed "+r.String(), func(fw firewall.Backend) error {
		port, _ := f.m.CurrentPort() // 0 when unknown: the guard refuses
		rules, err := fw.List()
		if err != nil {
			return err
		}
		if err := guard.Check(guard.Facts{SSHPort: port, Rules: rules}, guard.RemoveRule{Rule: r}); err != nil {
			return err
		}
		return fw.Remove(r)
	})
}

// change runs do on the host firewall through logMutation; the screen then shows
// done or the error, and reloads.
func (f firewallScreen) change(action, done string, do func(firewall.Backend) error) tea.Cmd {
	return func() tea.Msg {
		err := logMutation(f.m.Root, action, func() error {
			fw, err := firewall.New(f.m.Host, f.m.R, f.m.Pkgs)
			if err != nil {
				return err
			}
			return do(fw)
		})
		if err != nil {
			return changedMsg(err.Error())
		}
		return changedMsg(done)
	}
}

// parseRule reads "PORT[-END]/tcp|udp [from IP/CIDR]".
func parseRule(s string) (firewall.Rule, error) {
	usage := errors.New("want PORT[-END]/tcp|udp [from IP/CIDR], e.g. 8080/tcp")
	var r firewall.Rule
	f := strings.Fields(s)
	if len(f) == 3 && f[1] == "from" {
		r.From, f = f[2], f[:1]
	}
	if len(f) != 1 {
		return r, usage
	}
	spec, proto, _ := strings.Cut(f[0], "/")
	if proto != "tcp" && proto != "udp" {
		return r, errors.New("protocol must be tcp or udp")
	}
	r.Proto = proto
	start, end, isRange := strings.Cut(spec, "-")
	var err error
	if r.Port, err = strconv.Atoi(start); err != nil {
		return r, usage
	}
	if isRange {
		if r.End, err = strconv.Atoi(end); err != nil || r.End == 0 {
			return r, fmt.Errorf("invalid port range %s", spec)
		}
	}
	return r, r.Validate()
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
		var table strings.Builder
		tw := tabwriter.NewWriter(&table, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "Port\tProto\tSource\tListening")
		for _, r := range f.fw.rules {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", ports(r), cmp.Or(r.Proto, "any"), cmp.Or(r.From, "anywhere"), f.backed(r))
		}
		tw.Flush()
		lines := strings.Split(table.String(), "\n")
		lines[f.cursor+1] = selectedStyle.Render(lines[f.cursor+1])
		b.WriteString(strings.Join(lines, "\n"))
	}
	b.WriteString("\n\n")
	if f.adding {
		b.WriteString("open: " + f.input + "█\n" + dimStyle.Render("PORT[-END]/tcp|udp [from IP/CIDR] · enter open · esc cancel") + "\n")
	} else {
		b.WriteString(dimStyle.Render("a open a port · d remove selected rule") + "\n")
	}
	if f.status != "" {
		b.WriteString("\n" + f.status)
	}
	return tea.NewView(strings.TrimRight(b.String(), "\n"))
}

// backed says whether a Listening Port matches r's protocol inside its port range.
func (f firewallScreen) backed(r firewall.Rule) string {
	if f.fw.listening == nil {
		return "unknown"
	}
	end := max(r.End, r.Port)
	if slices.ContainsFunc(f.fw.listening, func(l listeningPort) bool {
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
