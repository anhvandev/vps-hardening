package tui

import (
	"fmt"
	"io"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
	"github.com/anhvandev/vpsctl/internal/updates"
)

func init() { screens["Updates"] = newUpdates }

// updatesScreen lists the pending updates, read from the package lists as
// they are, and whether a reboot is waiting. r refreshes the package lists,
// s installs the security updates (Yes/No), u all of them (type "all"), b
// reboots (type "reboot"); each runs as a Task, the package manager's output
// shown live, and the installs refresh the lists first.
type updatesScreen struct {
	m      *harden.Machine
	loaded bool
	up     updatesMsg
	table  table
	asking string // key of the button whose confirm is up, "" for none
	ask    confirm
	w, h   int
}

type updatesMsg struct {
	pkgs          []updates.Package
	err           error // not listed
	reboot, known bool
	kernel        string
}

func newUpdates(m *harden.Machine) tea.Model {
	return updatesScreen{m: m, table: newTable("PACKAGE", "CURRENT → NEW", "KIND")}
}

func (u updatesScreen) Init() tea.Cmd {
	return func() tea.Msg {
		var msg updatesMsg
		msg.pkgs, msg.err = updates.List(u.m.R, u.m.Host.PkgManager)
		msg.reboot, msg.known, msg.kernel = updates.RebootNeeded(u.m.R, u.m.Root, u.m.Host.PkgManager)
		return msg
	}
}

func (u updatesScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		u.w, u.h = msg.Width, msg.Height
		u.table.height = max(u.h-8, 3) // room for the header, notes and buttons
		u.table.setRows(u.table.rows)
		return u, nil
	case updatesMsg:
		u.up, u.loaded = msg, true
		u.table.setRows(u.rows())
		return u, nil
	case taskDoneMsg:
		return u, u.Init()
	case tea.MouseClickMsg:
		if m := mouse(u.layout(), msg); m != nil {
			return u.Update(m)
		}
		return u, nil
	}
	if u.asking != "" {
		c, ev := u.ask.update(msg)
		u.ask = c
		if ev == editing {
			return u, nil
		}
		key := u.asking
		u.asking = ""
		if ev == submitted {
			return u, u.run(key)
		}
		return u, nil
	}
	if t, ok := u.table.update(msg); ok {
		u.table = t
		return u, nil
	}
	k, ok := msg.(tea.KeyPressMsg)
	if !ok || disabled(u.buttons(), k.String()) {
		return u, nil
	}
	sec, all := u.counts()
	switch k.String() {
	case "esc":
		return u, Back
	case "s":
		u.asking, u.ask = "s", newConfirm(fmt.Sprintf("Install %d security update%s?", sec, plural(sec)))
	case "u":
		u.asking, u.ask = "u", newDangerous(fmt.Sprintf("Install all %d update%s", all, plural(all)), "Install", "all")
	case "b":
		u.asking, u.ask = "b", newDangerous("Reboot the machine", "Reboot", "reboot")
	case "r":
		return u, u.run("r")
	}
	return u, nil
}

// run starts the Task of the confirmed button key.
func (u updatesScreen) run(key string) tea.Cmd {
	mgr := u.m.Host.PkgManager
	refresh := taskStep{"Refresh package lists", func(r system.Runner, _ io.Writer) error { return updates.Refresh(r, mgr) }}
	switch key {
	case "r":
		return runTask("Refresh package lists", "updates refresh", "package lists refreshed", refresh)
	case "s":
		return runTask("Install security updates", "updates install security", "security updates installed", refresh,
			taskStep{"Install security updates", func(r system.Runner, _ io.Writer) error { return updates.Install(r, mgr, true) }})
	case "u":
		return runTask("Install all updates", "updates install all", "all updates installed", refresh,
			taskStep{"Install all updates", func(r system.Runner, _ io.Writer) error { return updates.Install(r, mgr, false) }})
	}
	reboot := taskStep{"Reboot", func(r system.Runner, _ io.Writer) error {
		res, err := r.Run("systemctl", "reboot")
		if err == nil && res.Code != 0 {
			err = fmt.Errorf("systemctl reboot: exit %d: %s", res.Code, strings.TrimSpace(res.Stderr))
		}
		return err
	}}
	return func() tea.Msg {
		return startTaskMsg{name: "Reboot", action: "reboot", summary: "rebooting; this SSH session will drop",
			steps: []taskStep{reboot}, logFirst: true}
	}
}

// counts is the number of security updates and of all updates pending.
func (u updatesScreen) counts() (sec, all int) {
	for _, p := range u.up.pkgs {
		if p.Security {
			sec++
		}
	}
	return sec, len(u.up.pkgs)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func (u updatesScreen) buttons() []button {
	sec, all := u.counts()
	bs := []button{{"s", "Install security", ""}, {"u", "Install all …", ""}, {"b", "Reboot …", ""}, {"r", "Refresh", ""}}
	switch {
	case !u.loaded:
		bs[0].why, bs[1].why = "loading", "loading"
	case sec == 0:
		bs[0].why = "no security updates pending"
	}
	if u.loaded && all == 0 {
		bs[1].why = "no updates pending"
	}
	return bs
}

func (u updatesScreen) typing() bool { return u.table.typing() || u.asking != "" && u.ask.typing() }

func (u updatesScreen) keys() string {
	switch {
	case u.asking != "":
		return u.ask.keys()
	case u.table.typing():
		return u.table.keys()
	}
	return u.table.keys() + " · " + keyHelp(u.buttons()) + " · esc back"
}

func (u updatesScreen) rows() [][]string {
	arrow := " → "
	if ascii.Load() {
		arrow = " -> "
	}
	var rows [][]string
	for _, p := range u.up.pkgs {
		kind := "other"
		if p.Security {
			kind = warnStyle.Render("security")
		}
		cur := p.Current
		if cur == "" {
			cur = "(new)"
		}
		rows = append(rows, []string{p.Name, cur + arrow + p.New, kind})
	}
	return rows
}

// summary is "N security · M other · reboot state".
func (u updatesScreen) summary() string {
	sec, all := u.counts()
	reboot := "reboot unknown"
	switch {
	case u.up.reboot:
		reboot = glyph("⚠") + " reboot required"
		if u.up.kernel != "" {
			reboot += " (kernel " + u.up.kernel + ")"
		}
		reboot = warnStyle.Render(reboot)
	case u.up.known:
		reboot = "no reboot required"
	}
	if u.up.err != nil {
		return reboot
	}
	return fmt.Sprintf("%d security · %d other · %s", sec, all-sec, reboot)
}

// layout is the screen: header, notes, table, buttons, and the confirm over them.
func (u updatesScreen) layout() *lipgloss.Compositor {
	title := titleStyle.Render("Updates")
	if !u.loaded {
		return stack(title, "", "loading…")
	}
	summary := u.summary()
	blocks := []any{title + strings.Repeat(" ", max(u.w-ansi.StringWidth(title)-ansi.StringWidth(summary), 1)) + summary}
	if u.up.err != nil {
		blocks = append(blocks, "updates unreadable: "+u.up.err.Error())
	} else {
		blocks = append(blocks, u.table.layer(u.w))
	}
	blocks = append(blocks, buttonRow(u.buttons()...))
	c := stack(blocks...)
	if u.asking != "" {
		c.AddLayers(u.ask.layer(u.w))
	}
	return c
}

func (u updatesScreen) View() tea.View { return tea.NewView(u.layout().Render()) }
