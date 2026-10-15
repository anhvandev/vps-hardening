package tui

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/anhvandev/vpsctl/internal/docker"
	"github.com/anhvandev/vpsctl/internal/firewall"
	"github.com/anhvandev/vpsctl/internal/guard"
	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

func init() { screens["Firewall"] = newFirewall }

// firewallScreen lists every Firewall Rule read live from ufw/firewalld (rules
// added by hand included), each with the Listening Port behind it. a opens a
// port or range, d removes the selected rule after a Yes/No; both run as
// Tasks. Rules the Lockout Guard protects are marked ◆ and their Remove is
// disabled with the reason; the guard checks again under the lock. Docker
// Published Ports on all interfaces follow the rules as rows that bypass the
// firewall, with the fix; o opens the container in Docker.
type firewallScreen struct {
	m      *harden.Machine
	loaded bool
	fw     firewallMsg
	table  table
	adding bool // the open-a-port form is up
	form   form
	asking bool // the remove confirm is up, for target
	ask    confirm
	target firewall.Rule
	w, h   int
}

type firewallMsg struct {
	state     string
	rules     []firewall.Rule
	err       error           // rules not listed
	listening []listeningPort // nil if ss failed
	sshPort   int             // 0 when unknown
	published []openPort      // Docker ports that bypass the firewall
}

func newFirewall(m *harden.Machine) tea.Model {
	return firewallScreen{m: m, table: newTable("PORT", "PROTO", "SOURCE", "LISTENING", "NOTE")}
}

func (f firewallScreen) Init() tea.Cmd {
	return func() tea.Msg {
		var msg firewallMsg
		msg.state, msg.rules, msg.err = firewallRules(f.m)
		msg.listening = listeningPorts(f.m.R)
		msg.sshPort, _ = f.m.CurrentPort()
		cs, _ := docker.Containers(f.m.R) // no Docker: no rows
		msg.published = openPorts(cs)
		return msg
	}
}

func (f firewallScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		f.w, f.h = msg.Width, msg.Height
		f.table.height = max(f.h-14, 3) // room for the header, detail box and buttons or form
		f.table.setRows(f.table.rows)
		return f, nil
	case firewallMsg:
		f.fw, f.loaded = msg, true
		f.table.setRows(f.rows())
		return f, nil
	case taskDoneMsg:
		return f, f.Init()
	case tea.MouseClickMsg:
		if m := mouse(f.layout(), msg); m != nil {
			return f.Update(m)
		}
		return f, nil
	}
	switch {
	case f.adding:
		return f.formUpdate(msg)
	case f.asking:
		c, ev := f.ask.update(msg)
		f.ask, f.asking = c, ev == editing
		if ev == submitted {
			return f, f.remove(f.target)
		}
		return f, nil
	}
	if t, ok := f.table.update(msg); ok {
		f.table = t
		return f, nil
	}
	k, ok := msg.(tea.KeyPressMsg)
	if !ok || disabled(f.buttons(), k.String()) {
		return f, nil
	}
	switch k.String() {
	case "esc":
		return f, Back
	case "a":
		f.adding, f.form = true, newForm("Open a port", "Port")
		f.form.inputs[0].Placeholder = "PORT[-END]/tcp|udp [from IP/CIDR], e.g. 8080/tcp"
	case "d":
		f.target = f.fw.rules[f.table.selected()]
		f.asking, f.ask = true, newConfirm("Remove rule "+f.target.String()+"?")
	case "r":
		return f, f.Init()
	case "o":
		if op, ok := f.published(); ok {
			return f, func() tea.Msg { return openMsg{"Docker", op.c.Name} }
		}
	}
	return f, nil
}

// published is the selected Published Port; ok is false on a rule.
func (f firewallScreen) published() (openPort, bool) {
	i := f.table.selected() - len(f.fw.rules)
	if i < 0 || i >= len(f.fw.published) {
		return openPort{}, false
	}
	return f.fw.published[i], true
}

// formUpdate edits the open-a-port form; enter validates, then opens.
func (f firewallScreen) formUpdate(msg tea.Msg) (tea.Model, tea.Cmd) {
	fm, ev := f.form.update(msg)
	f.form, f.adding = fm, ev == editing
	if ev != submitted {
		return f, nil
	}
	r, err := parseRule(f.form.value(0))
	if err != nil {
		f.form.err, f.adding = err.Error(), true
		return f, nil
	}
	return f, runTask("Open port "+r.String(), "firewall open "+r.String(), "opened "+r.String(),
		f.step("Allow "+r.String(), func(fw firewall.Backend) error { return fw.Allow(r) }))
}

func (f firewallScreen) typing() bool {
	return f.adding || f.table.typing() || f.asking && f.ask.typing()
}

func (f firewallScreen) keys() string {
	switch {
	case f.adding:
		return f.form.keys()
	case f.asking:
		return f.ask.keys()
	case f.table.typing():
		return f.table.keys()
	}
	return f.table.keys() + " · " + keyHelp(f.buttons()) + " · esc back"
}

// refusal is why the Lockout Guard would refuse removing r, "" if it allows it.
func (f firewallScreen) refusal(r firewall.Rule) string {
	err := guard.Check(guard.Facts{SSHPort: f.fw.sshPort, Rules: f.fw.rules}, guard.RemoveRule{Rule: r})
	if err != nil {
		return strings.TrimPrefix(err.Error(), "refused: ")
	}
	return ""
}

func (f firewallScreen) buttons() []button {
	rm := button{"d", "Remove", "no rule selected"}
	if _, ok := f.published(); ok {
		rm.why = "a Published Port is changed in Docker, not in the firewall"
		return []button{{"a", "+ Open port", ""}, rm, {"r", "Refresh", ""}, {"o", "Open in Docker", ""}}
	}
	if i := f.table.selected(); i >= 0 {
		rm.why = f.refusal(f.fw.rules[i])
	}
	return []button{{"a", "+ Open port", ""}, rm, {"r", "Refresh", ""}}
}

// rows are the table rows, one per rule (rules the guard protects are marked
// ◆), then one per Published Port.
func (f firewallScreen) rows() [][]string {
	var rows [][]string
	listening := func(r firewall.Rule) string {
		if _, ok := f.listening(r); ok {
			return okStyle.Render(glyph("●")) + " " + f.listener(r)
		}
		return naStyle.Render(glyph("·") + " " + f.listener(r))
	}
	for _, r := range f.fw.rules {
		note := ""
		if f.refusal(r) != "" {
			note = glyph("◆")
			if f.fw.sshPort >= r.Port && f.fw.sshPort <= max(r.End, r.Port) {
				note = "SSH " + note
			}
		}
		rows = append(rows, []string{ports(r), cmp.Or(r.Proto, "any"), cmp.Or(r.From, "any"), listening(r), note})
	}
	for _, op := range f.fw.published {
		start, end, _ := strings.Cut(op.p.HostPort, "-")
		r := firewall.Rule{Proto: op.p.Proto}
		r.Port, _ = strconv.Atoi(start)
		r.End, _ = strconv.Atoi(end)
		rows = append(rows, []string{op.p.HostPort, op.p.Proto, "(Docker)", listening(r),
			warnStyle.Render(glyph("⚠")) + " Published Port, bypasses firewall"})
	}
	return rows
}

// layout is the screen: header, rules table, detail box, buttons (or the
// form), and the confirm over them.
func (f firewallScreen) layout() *lipgloss.Compositor {
	if !f.loaded {
		return stack(titleStyle.Render("Firewall"), "", "loading…")
	}
	name := map[string]string{"debian": "ufw · ", "rhel": "firewalld · "}[f.m.Host.Family]
	summary := name + f.fw.state
	if f.fw.err == nil {
		summary += fmt.Sprintf(" · %d rules", len(f.fw.rules))
	}
	title := titleStyle.Render("Firewall")
	blocks := []any{title + strings.Repeat(" ", max(f.w-ansi.StringWidth(title)-ansi.StringWidth(summary), 1)) + summary}
	switch {
	case f.fw.err != nil && f.fw.state == "active":
		blocks = append(blocks, "rules unreadable: "+f.fw.err.Error())
	case f.fw.err != nil:
	default:
		blocks = append(blocks, f.table.layer(f.w))
		if op, ok := f.published(); ok && f.h >= 26 {
			blocks = append(blocks, detailBox(op.p.HostPort+"/"+op.p.Proto, op.fix(firewallName(f.m)), f.w, 3))
		} else if i := f.table.selected(); i >= 0 && !ok && f.h >= 26 {
			blocks = append(blocks, detailBox(f.fw.rules[i].String(), f.detail(f.fw.rules[i]), f.w, 3))
		}
	}
	if f.adding {
		blocks = append(blocks, "", f.form.view())
	} else {
		blocks = append(blocks, buttonRow(f.buttons()...))
	}
	c := stack(blocks...)
	if f.asking {
		c.AddLayers(f.ask.layer(f.w))
	}
	return c
}

func (f firewallScreen) View() tea.View { return tea.NewView(f.layout().Render()) }

// detail describes r, with the Lockout Guard's reason when it protects r.
func (f firewallScreen) detail(r firewall.Rule) string {
	s := fmt.Sprintf("Allows %s %s from %s. Listening: %s.", cmp.Or(r.Proto, "tcp and udp"), ports(r), cmp.Or(r.From, "anywhere"), f.listener(r))
	if why := f.refusal(r); why != "" {
		s += "\n" + warnStyle.Render(glyph("◆")+" Remove is disabled by the Lockout Guard: "+why)
	}
	return s
}

// remove deletes exactly r as a Task unless the Lockout Guard refuses,
// deciding on the SSH port and rules read under the lock.
func (f firewallScreen) remove(r firewall.Rule) tea.Cmd {
	return runTask("Remove rule "+r.String(), "firewall remove "+r.String(), "removed "+r.String(),
		f.step("Lockout Guard check", func(fw firewall.Backend) error {
			port, _ := f.m.CurrentPort() // 0 when unknown: the guard refuses
			rules, err := fw.List()
			if err != nil {
				return err
			}
			return guard.Check(guard.Facts{SSHPort: port, Rules: rules}, guard.RemoveRule{Rule: r})
		}),
		f.step("Remove "+r.String(), func(fw firewall.Backend) error { return fw.Remove(r) }))
}

// step is a Task step that runs do on the host firewall.
func (f firewallScreen) step(name string, do func(firewall.Backend) error) taskStep {
	return taskStep{name, func(r system.Runner, _ io.Writer) error {
		fw, err := firewall.New(f.m.Host, r, f.m.Pkgs)
		if err != nil {
			return err
		}
		return do(fw)
	}}
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

// listening is the first Listening Port matching r's protocol inside its
// port range; ok is false when there is none or ss failed.
func (f firewallScreen) listening(r firewall.Rule) (l listeningPort, ok bool) {
	for _, l := range f.fw.listening {
		if (r.Proto == "" || r.Proto == l.proto) && l.port >= r.Port && l.port <= max(r.End, r.Port) {
			return l, true
		}
	}
	return l, false
}

// listener names what listens behind r: the process, "nothing" or "unknown"
// (ss failed).
func (f firewallScreen) listener(r firewall.Rule) string {
	l, ok := f.listening(r)
	switch {
	case f.fw.listening == nil:
		return "unknown"
	case !ok:
		return "nothing"
	}
	return cmp.Or(l.process, "a process")
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
