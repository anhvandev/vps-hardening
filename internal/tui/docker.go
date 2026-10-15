package tui

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync/atomic"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/anhvandev/vpsctl/internal/docker"
	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

func init() { screens["Docker"] = newDocker }

// noDocker hides the Docker menu item; New sets it from the machine.
var noDocker atomic.Bool

// dockerScreen lists the containers read live, grouped by compose project
// (plain containers last), with their Published Ports; ports bound to all
// interfaces are flagged ⚠ with how to fix them. s/x/R start, stop and
// restart the selected container as a Task after a confirm; l follows its
// logs. Re-read on every refresh tick while open. vpsctl never edits Docker's
// firewall rules.
type dockerScreen struct {
	m      *harden.Machine
	loaded bool
	list   []docker.Container
	err    error // docker not reachable
	table  table
	want   string // container to select once loaded (opened from a link)
	asking bool
	ask    confirm
	verb   [2]string // the dockerVerbs entry asked about
	target string    // the container asked about (a refresh may move the selection)
	w, h   int
}

// dockerVerbs maps a key to its docker verb and what to say once done.
var dockerVerbs = map[string][2]string{"s": {"start", "started"}, "x": {"stop", "stopped"}, "R": {"restart", "restarted"}}

// dockerMsg is a read of the containers.
type dockerMsg struct {
	list []docker.Container
	err  error
}

// openMsg asks the shell to open the screen title on its item.
type openMsg struct{ title, item string }

func newDocker(m *harden.Machine) tea.Model {
	return dockerScreen{m: m, table: newTable("CONTAINER", "PROJECT", "STATE", "PORTS", "IMAGE")}
}

func (d dockerScreen) Init() tea.Cmd { return d.load() }

func (d dockerScreen) load() tea.Cmd {
	return func() tea.Msg {
		list, err := docker.Containers(d.m.R)
		slices.SortStableFunc(list, func(a, b docker.Container) int {
			switch { // plain containers last
			case a.Project == "" && b.Project != "":
				return 1
			case a.Project != "" && b.Project == "":
				return -1
			}
			return cmp.Or(cmp.Compare(a.Project, b.Project), cmp.Compare(a.Name, b.Name))
		})
		return dockerMsg{list, err}
	}
}

func (d dockerScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		d.w, d.h = msg.Width, msg.Height
		d.table.height = max(d.h-14, 3)
		d.table.setRows(d.table.rows)
		return d, nil
	case openMsg:
		d.want = msg.item
		return d, nil
	case dockerMsg:
		d.list, d.err, d.loaded = msg.list, msg.err, true
		if i := slices.IndexFunc(d.list, func(c docker.Container) bool { return c.Name == d.want }); i >= 0 {
			d.table.cursor, d.want = i, ""
		}
		d.table.setRows(d.rows())
		return d, nil
	case refreshMsg, taskDoneMsg:
		return d, d.load()
	case tea.MouseClickMsg:
		if m := mouse(d.layout(), msg); m != nil {
			return d.Update(m)
		}
		return d, nil
	}
	if d.asking {
		c, ev := d.ask.update(msg)
		d.ask, d.asking = c, ev == editing
		if ev == submitted {
			return d, d.run(d.verb, d.target)
		}
		return d, nil
	}
	if t, ok := d.table.update(msg); ok {
		d.table = t
		return d, nil
	}
	k, ok := msg.(tea.KeyPressMsg)
	if !ok || disabled(d.buttons(), k.String()) {
		return d, nil
	}
	switch k.String() {
	case "esc":
		return d, Back
	case "r":
		return d, d.load()
	case "l":
		return openDockerLogs(d, d.list[d.table.selected()].Name)
	}
	if v, ok := dockerVerbs[k.String()]; ok {
		d.verb, d.target, d.asking = v, d.list[d.table.selected()].Name, true
		d.ask = newConfirm(strings.ToUpper(v[0][:1]) + v[0][1:] + " " + d.target + "?")
	}
	return d, nil
}

// run runs verb (a dockerVerbs entry) on the container named name as a Task.
func (d dockerScreen) run(verb [2]string, name string) tea.Cmd {
	title := strings.ToUpper(verb[0][:1]) + verb[0][1:] + " " + name
	return runTask(title, "docker "+verb[0]+" "+name, verb[1]+" "+name,
		taskStep{title, func(r system.Runner, _ io.Writer) error { return docker.Do(r, verb[0], name) }})
}

func (d dockerScreen) typing() bool { return d.table.typing() || d.asking && d.ask.typing() }

func (d dockerScreen) keys() string {
	switch {
	case d.asking:
		return d.ask.keys()
	case d.table.typing():
		return d.table.keys()
	}
	return d.table.keys() + " · " + keyHelp(d.buttons()) + " · esc back"
}

// buttons are the actions on the selected container, then Refresh.
func (d dockerScreen) buttons() []button {
	bs := []button{{"s", "Start", ""}, {"x", "Stop", ""}, {"R", "Restart", ""}, {"l", "Logs", ""}}
	i := d.table.selected()
	for j := range bs {
		switch {
		case i < 0 || d.err != nil:
			bs[j].why = "no container selected"
		case bs[j].key == "s" && d.list[i].State == "running":
			bs[j].why = "already running"
		case bs[j].key == "x" && d.list[i].State != "running":
			bs[j].why = "not running"
		}
	}
	return append(bs, button{"r", "Refresh", ""})
}

func (d dockerScreen) rows() [][]string {
	var rows [][]string
	for _, c := range d.list {
		rows = append(rows, []string{c.Name, cmp.Or(c.Project, "-"), containerState(c), portsCell(c), c.Image})
	}
	return rows
}

func (d dockerScreen) layout() *lipgloss.Compositor {
	title := titleStyle.Render("Docker")
	switch {
	case !d.loaded:
		return stack(title, "", "loading…")
	case d.err != nil:
		return stack(title, "", "Docker is not reachable: "+d.err.Error(), "", buttonRow(d.buttons()...))
	}
	summary := fmt.Sprintf("%d containers", len(d.list))
	if n := len(openPorts(d.list)); n > 0 {
		summary += " · " + warnStyle.Render(glyph("⚠")) + " " + publishedPorts(n)
	}
	blocks := []any{title + strings.Repeat(" ", max(d.w-ansi.StringWidth(title)-ansi.StringWidth(summary), 1)) + summary,
		d.table.layer(d.w)}
	if i := d.table.selected(); i >= 0 && d.h >= 26 {
		blocks = append(blocks, detailBox(d.list[i].Name, d.detail(d.list[i]), d.w, 3))
	}
	c := stack(append(blocks, buttonRow(d.buttons()...))...)
	if d.asking {
		c.AddLayers(d.ask.layer(d.w))
	}
	return c
}

func (d dockerScreen) View() tea.View { return tea.NewView(d.layout().Render()) }

// detail is the container's image and status, then the fix for each of its
// ports open on all interfaces.
func (d dockerScreen) detail(c docker.Container) string {
	s := c.Image + " · " + c.Status
	if c.Project != "" {
		s += " · compose project " + c.Project
	}
	for _, op := range openPorts([]docker.Container{c}) {
		s += "\n" + warnStyle.Render(glyph("⚠")+" "+op.p.HostPort+"/"+op.p.Proto+": ") + op.fix(firewallName(d.m))
	}
	return s
}

func containerState(c docker.Container) string {
	switch c.State {
	case "running":
		return okStyle.Render(glyph("●")) + " running"
	case "restarting", "dead", "paused":
		return warnStyle.Render(glyph("⚠")) + " " + c.State
	case "exited": // "Exited (0) 2 days ago" -> exited(0)
		_, rest, _ := strings.Cut(c.Status, "Exited ")
		code, _, _ := strings.Cut(rest, " ")
		return naStyle.Render(glyph("·") + " exited" + code)
	}
	return naStyle.Render(glyph("·") + " " + c.State)
}

// portsCell is c's Published Ports, IPv4 and IPv6 bindings of one port
// shown once; those on all interfaces are flagged ⚠.
func portsCell(c docker.Container) string {
	var ps []string
	seen := map[string]bool{}
	for _, p := range c.Published() {
		if k := p.HostPort + ">" + p.Port + "/" + p.Proto; !seen[k] {
			seen[k] = true
			s := p.HostIP + ":" + p.HostPort + "→" + p.Port
			if p.Proto != "tcp" {
				s += "/" + p.Proto
			}
			if p.AllInterfaces() {
				s = warnStyle.Render(glyph("⚠")) + " " + s
			}
			ps = append(ps, s)
		}
	}
	return cmp.Or(strings.Join(ps, ", "), "-")
}

// openPort is a Published Port on all interfaces: it bypasses the firewall.
type openPort struct {
	c docker.Container
	p docker.Port
}

// openPorts is cs's Published Ports on all interfaces, once per host port
// and protocol (docker lists the IPv4 and IPv6 bindings apart).
func openPorts(cs []docker.Container) []openPort {
	var ops []openPort
	seen := map[string]bool{}
	for _, c := range cs {
		for _, p := range c.Published() {
			if k := p.HostPort + "/" + p.Proto; p.AllInterfaces() && !seen[k] {
				seen[k] = true
				ops = append(ops, openPort{c, p})
			}
		}
	}
	return ops
}

// fix says who publishes the port, why the firewall named fw doesn't
// protect it and how to fix it.
func (op openPort) fix(fw string) string {
	by := op.c.Name
	if op.c.Project != "" {
		by += " (compose: " + op.c.Project + ")"
	}
	return fmt.Sprintf("Published by container %s. Reachable from the internet regardless of %s. "+
		"Fix: publish as 127.0.0.1:%s:%s and front it with a reverse proxy. vpsctl never edits Docker's firewall rules.",
		by, fw, op.p.HostPort, op.p.Port)
}

func firewallName(m *harden.Machine) string {
	return cmp.Or(map[string]string{"debian": "ufw", "rhel": "firewalld"}[m.Host.Family], "the firewall")
}

func publishedPorts(n int) string {
	if n == 1 {
		return "1 Published Port"
	}
	return fmt.Sprintf("%d Published Ports", n)
}

// dockerState is the Overview's Docker line.
func dockerState(r system.Runner) string {
	cs, err := docker.Containers(r)
	switch {
	case errors.Is(err, docker.ErrNotInstalled):
		return "not installed"
	case err != nil:
		return "not reachable: " + err.Error()
	}
	s := fmt.Sprintf("%d containers", len(cs))
	if n := len(openPorts(cs)); n > 0 {
		s += " · " + warnStyle.Render(glyph("⚠")) + " " + publishedPorts(n) + " bypassing the firewall"
	}
	return s
}
