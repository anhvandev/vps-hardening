package tui

import (
	"fmt"
	"io"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/anhvandev/vpsctl/internal/fail2ban"
	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

func init() { screens["fail2ban"] = newFail2ban }

// f2bScreen lists jails and banned IPs, re-read on every refresh tick while open;
// u unbans the selected IP and a adds an IP or CIDR (the operator's session
// IP suggested) to the ignore list in vpsctl's jail drop-in, each as a Task.
type f2bScreen struct {
	m      *harden.Machine
	state  *f2bState // nil while loading
	table  table
	adding bool // the ignore-list form is up
	form   form
	w, h   int
}

// f2bState is one read of the live fail2ban.
type f2bState struct {
	down   string // "not installed" or "not running"; "" when running
	jails  []string
	rows   []fail2ban.Ban // the table's rows: each ban, IP "" for a jail without
	ignore []string       // ignoreip in the drop-in
}

// f2bMsg is a read of fail2ban.
type f2bMsg struct{ state *f2bState }

func newFail2ban(m *harden.Machine) tea.Model {
	return f2bScreen{m: m, table: newTable("JAIL", "BANNED IP")}
}

func (f f2bScreen) Init() tea.Cmd { return f.load() }

func (f f2bScreen) load() tea.Cmd {
	return func() tea.Msg { return f2bMsg{readF2b(f.m)} }
}

func readF2b(m *harden.Machine) *f2bState {
	jails, err := fail2ban.Jails(m.R)
	if err != nil {
		return &f2bState{down: err.Error()}
	}
	s := &f2bState{jails: jails, ignore: fail2ban.Ignore(m.Root)}
	bans := fail2ban.Bans(m.R, jails)
	for _, j := range jails {
		n := len(s.rows)
		for _, b := range bans {
			if b.Jail == j {
				s.rows = append(s.rows, b)
			}
		}
		if len(s.rows) == n {
			s.rows = append(s.rows, fail2ban.Ban{Jail: j})
		}
	}
	return s
}

func (f f2bScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		f.w, f.h = msg.Width, msg.Height
		f.table.height = max(f.h-10, 3) // room for the header, ignore list and buttons or form
		f.table.setRows(f.table.rows)
		return f, nil
	case f2bMsg:
		f.state = msg.state
		f.table.setRows(f.tableRows())
		return f, nil
	case refreshMsg, taskDoneMsg:
		return f, f.load()
	case tea.MouseClickMsg:
		if m := mouse(f.layout(), msg); m != nil {
			return f.Update(m)
		}
		return f, nil
	}
	if f.adding {
		return f.formUpdate(msg)
	}
	if f.state != nil && f.state.down == "" {
		if t, ok := f.table.update(msg); ok {
			f.table = t
			return f, nil
		}
	}
	k, ok := msg.(tea.KeyPressMsg)
	if !ok || disabled(f.buttons(), k.String()) {
		return f, nil
	}
	switch k.String() {
	case "esc":
		return f, Back
	case "a":
		f.adding, f.form = true, newForm("Add to the ignore list", "IP or CIDR")
		f.form.inputs[0].SetValue(sessionIP(f.m.Root))
	case "u":
		b := f.state.rows[f.table.selected()]
		return f, runTask("Unban "+b.IP, "fail2ban unban "+b.IP+" "+b.Jail, "unbanned "+b.IP+" from "+b.Jail,
			taskStep{"Unban " + b.IP + " in " + b.Jail, func(r system.Runner, _ io.Writer) error { return fail2ban.Unban(r, b) }})
	case "r":
		return f, f.load()
	}
	return f, nil
}

// formUpdate edits the ignore-list form; enter validates, then adds.
func (f f2bScreen) formUpdate(msg tea.Msg) (tea.Model, tea.Cmd) {
	fm, ev := f.form.update(msg)
	f.form, f.adding = fm, ev == editing
	if ev != submitted {
		return f, nil
	}
	entry := strings.TrimSpace(f.form.value(0))
	if !fail2ban.ValidIgnore(entry) {
		f.form.err, f.adding = fmt.Sprintf("%q is not an IP or CIDR", entry), true
		return f, nil
	}
	return f, runTask("Ignore "+entry, "fail2ban ignore "+entry, "added "+entry+" to the ignore list",
		taskStep{"Add " + entry + " to ignoreip and reload", func(r system.Runner, _ io.Writer) error {
			return fail2ban.AddIgnore(r, f.m.Root, entry)
		}})
}

func (f f2bScreen) typing() bool { return f.adding || f.table.typing() }

func (f f2bScreen) keys() string {
	switch {
	case f.adding:
		return f.form.keys()
	case f.table.typing():
		return f.table.keys()
	case f.state == nil || f.state.down != "":
		return "esc back"
	}
	return f.table.keys() + " · " + keyHelp(f.buttons()) + " · esc back"
}

func (f f2bScreen) buttons() []button {
	if f.state == nil || f.state.down != "" {
		return []button{{"u", "Unban", "fail2ban is not running"}, {"a", "+ Ignore IP", "fail2ban is not running"}, {"r", "Refresh", ""}}
	}
	unban := button{"u", "Unban", "no banned IP selected"}
	if i := f.table.selected(); i >= 0 && f.state.rows[i].IP != "" {
		unban.why = ""
	}
	return []button{unban, {"a", "+ Ignore IP", ""}, {"r", "Refresh", ""}}
}

func (f f2bScreen) tableRows() [][]string {
	var rows [][]string
	for _, b := range f.state.rows {
		ip := b.IP
		if ip == "" {
			ip = naStyle.Render("no bans")
		}
		rows = append(rows, []string{b.Jail, ip})
	}
	return rows
}

func (f f2bScreen) layout() *lipgloss.Compositor {
	title := titleStyle.Render("fail2ban")
	switch {
	case f.state == nil:
		return stack(title, "", "loading…")
	case f.state.down != "":
		return stack(title, "", "fail2ban is "+f.state.down)
	}
	banned := 0
	for _, b := range f.state.rows {
		if b.IP != "" {
			banned++
		}
	}
	summary := fmt.Sprintf("%d jails · %d banned", len(f.state.jails), banned)
	blocks := []any{title + strings.Repeat(" ", max(f.w-ansi.StringWidth(title)-ansi.StringWidth(summary), 1)) + summary}
	if len(f.state.jails) == 0 {
		blocks = append(blocks, "no jails")
	} else {
		blocks = append(blocks, f.table.layer(f.w))
	}
	ignore := "none"
	if len(f.state.ignore) > 0 {
		ignore = strings.Join(f.state.ignore, " ")
	}
	blocks = append(blocks, "Ignore list: "+ignore)
	if f.adding {
		blocks = append(blocks, "", f.form.view())
	} else {
		blocks = append(blocks, buttonRow(f.buttons()...))
	}
	return stack(blocks...)
}

func (f f2bScreen) View() tea.View { return tea.NewView(f.layout().Render()) }
