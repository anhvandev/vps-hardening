package tui

import (
	"cmp"
	"io"
	"os"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/anhvandev/vpsctl/internal/guard"
	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/service"
	"github.com/anhvandev/vpsctl/internal/system"
)

func init() { screens["Services"] = newServices }

// servicesScreen lists Services read live (re-read on every refresh tick):
// running, enabled or failed ones by default, all with the filter dropdown
// (f); / filters by name. Start, stop, restart, enable, disable and revert
// ask Yes/No, then run as Tasks; buttons the Lockout Guard refuses (Protected
// Units, marked ◆) are disabled with the reason. l or enter opens the journal
// (journal.go); e edits the override in $EDITOR (unit_edit.go); a opens the
// new-Service form (services_create.go).
type servicesScreen struct {
	m      *harden.Machine
	loaded bool
	list   []service.Service
	err    error // list unreadable
	all    bool  // filter: all Services, not only running·enabled·failed
	table  table
	status string
	edit   *unitEdit // override being edited, nil if none
	form   *form     // new-Service form, nil if closed
	await  *awaited  // a create or enable+start Task the screen acts on once done
	asking bool      // the confirm is up, for act
	ask    confirm
	act    tea.Cmd // what yes runs
	pick   string  // unit to select once the list is re-read
	w, h   int
}

// servicesMsg is one read of the Services.
type servicesMsg struct {
	list []service.Service
	err  error
}

func newServices(m *harden.Machine) tea.Model {
	return servicesScreen{m: m, table: newTable("UNIT", "STATE", "ENABLED", "NOTE")}
}

func (s servicesScreen) Init() tea.Cmd { return s.reload() }

func (s servicesScreen) reload() tea.Cmd {
	return func() tea.Msg {
		list, err := service.List(s.m.R)
		return servicesMsg{list, err}
	}
}

// units is the list narrowed by the filter dropdown: the table's rows.
func (s servicesScreen) units() []service.Service {
	var out []service.Service
	for _, svc := range s.list {
		if s.all || svc.Sub == "running" || svc.Enabled == "enabled" || svc.Active == "failed" {
			out = append(out, svc)
		}
	}
	return out
}

// selected is the selected Service's name, "" if none.
func (s servicesScreen) selected() string {
	if i := s.table.selected(); i >= 0 {
		return s.units()[i].Name
	}
	return ""
}

// lifecycle maps a button key to its systemctl verb, label and past tense.
var lifecycle = []struct{ key, verb, label, done string }{
	{"s", "start", "Start", "started"}, {"x", "stop", "Stop", "stopped"}, {"R", "restart", "Restart", "restarted"},
	{"E", "enable", "Enable", "enabled"}, {"D", "disable", "Disable", "disabled"},
}

func (s servicesScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		s.w, s.h = msg.Width, msg.Height
		s.table.height = max(s.h-16, 3) // room for the header, detail box, buttons and status
		s.table.setRows(s.rows())
		return s, nil
	case servicesMsg:
		s.list, s.err, s.loaded = msg.list, msg.err, true
		s.table.setRows(s.rows())
		if s.pick != "" {
			s, s.pick = s.selectUnit(s.pick), ""
		}
		return s, nil
	case refreshMsg:
		return s, s.reload()
	case openMsg: // Overview links to a failed Service
		s.pick = msg.item
		return s, nil
	case taskDoneMsg:
		return s.taskDone()
	case tea.MouseClickMsg:
		if m := mouse(s.layout(), msg); m != nil {
			return s.Update(m)
		}
		return s, nil
	}
	if !s.table.typing() {
		if cmd, ok := s.flow().update(&s.edit, &s.status, msg); ok {
			return s, cmd
		}
	}
	switch {
	case s.form != nil:
		return s.formUpdate(msg)
	case s.asking:
		c, ev := s.ask.update(msg)
		s.ask, s.asking = c, ev == editing
		if ev == submitted {
			return s, s.act
		}
		if ev == cancelled && s.await != nil { // the enable+start offer declined
			s.status, s.await = "created "+s.await.unit+", not enabled or started", nil
		}
		return s, nil
	}
	if t, ok := s.table.update(msg); ok {
		s.table = t
		return s, nil
	}
	k, ok := msg.(tea.KeyPressMsg)
	if !ok || disabled(s.buttons(), k.String()) {
		return s, nil
	}
	unit := s.selected()
	switch key := k.String(); key {
	case "esc":
		return s, Back
	case "f":
		s.all = !s.all
		s.table.setRows(s.rows())
	case "l", "enter":
		return openJournal(s, s.m, unit, s.w, s.h)
	case "e":
		return s, s.flow().start(&s.edit, &s.status, unit)
	case "U":
		s.asking, s.ask, s.act = true, newConfirm("Revert "+unit+" override?"), s.flow().revert(unit)
	case "a":
		return s.openForm(), nil
	default:
		for _, l := range lifecycle {
			if l.key == key {
				s.asking, s.ask = true, newConfirm(l.label+" "+unit+"?")
				s.act = runTask(l.label+" "+unit, "service "+l.verb+" "+unit, l.done+" "+unit, unitStep(l.verb, unit))
			}
		}
	}
	return s, nil
}

// unitStep is the Task step `systemctl verb unit` (the Lockout Guard
// decides again inside service.Do).
func unitStep(verb, unit string) taskStep {
	return taskStep{"systemctl " + verb + " " + unit, func(r system.Runner, _ io.Writer) error {
		return service.Do(r, verb, unit)
	}}
}

func (s servicesScreen) flow() overrideFlow {
	return overrideFlow{s.m, "service", "[Service]\n"}
}

// taskDone reloads after a Task, finishing the edit, create or
// enable+start the screen waits on.
func (s servicesScreen) taskDone() (tea.Model, tea.Cmd) {
	created := s.flow().done(&s.edit, &s.status)
	if a := s.await; a != nil && !s.asking {
		s.await = nil
		switch {
		case a.what == "create" && a.ok.Load():
			created = a.unit
		case a.what == "start" && !a.ok.Load():
			s.status = "l opens " + a.unit + "'s journal"
		}
	}
	if created != "" { // offer to enable and start it, the unit selected
		s.form, s.status, s.pick = nil, "", created
		s.await = &awaited{what: "start", unit: created}
		s.asking, s.ask = true, newConfirm("Enable and start "+created+" now?")
		s.act = enableStart(s.await)
	}
	return s, s.reload()
}

func (s servicesScreen) typing() bool {
	return s.form != nil || s.table.typing() || s.asking && s.ask.typing()
}

func (s servicesScreen) keys() string {
	switch {
	case s.edit != nil && s.edit.failed:
		return "enter re-edit · esc discard"
	case s.form != nil:
		return s.form.keys() + " · ctrl+e advanced ($EDITOR)"
	case s.asking:
		return s.ask.keys()
	case s.table.typing():
		return s.table.keys()
	}
	// The buttons' keys, compact: nine of them don't fit the status bar one by
	// one; s x R E D are the lifecycle buttons in order.
	return "s x R E D · l journal · e edit · U revert · a new · f filter · / name · esc back"
}

// refusal is why the Lockout Guard would refuse verb on unit, "" if it allows it.
func refusal(unit, verb string) string {
	if err := guard.Check(guard.Facts{}, guard.UnitAction{Unit: unit, Verb: verb}); err != nil {
		return strings.TrimPrefix(err.Error(), "refused: ")
	}
	return ""
}

// buttons are the actions on the selected Service: lifecycle first, then the rest.
func (s servicesScreen) buttons() []button {
	unit := s.selected()
	var bs []button
	for _, l := range lifecycle {
		bs = append(bs, button{l.key, l.label, refusal(unit, l.verb)})
	}
	bs = append(bs, button{"l", "Journal", ""}, button{"e", "Edit", refusal(unit, "edit")}, button{"U", "Revert", refusal(unit, "edit")})
	for i := range bs {
		if unit == "" {
			bs[i].why = "no Service selected"
		}
	}
	if bs[len(bs)-1].why == "" && !hasOverride(s.m.Root, unit) {
		bs[len(bs)-1].why = "no override to revert"
	}
	return append(bs, button{"a", "+ New", ""})
}

func hasOverride(root, unit string) bool {
	_, err := os.Stat(service.OverridePath(root, unit))
	return err == nil
}

// rows are the table rows, one per Service the dropdown shows.
func (s servicesScreen) rows() [][]string {
	var rows [][]string
	for _, svc := range s.units() {
		st := naStyle.Render(glyph("·") + " " + svc.Sub)
		switch {
		case svc.Active == "failed":
			st = errStyle.Render(glyph("✗") + " failed")
		case svc.Active == "active":
			st = okStyle.Render(glyph("●")) + " " + svc.Sub
		}
		enabled := dimStyle.Render(cmp.Or(svc.Enabled, "—"))
		if svc.Enabled == "enabled" {
			enabled = okStyle.Render(glyph("●"))
		}
		note := ""
		if refusal(svc.Name, "stop") != "" {
			note = glyph("◆") + " Protected Unit"
		}
		rows = append(rows, []string{svc.Name, st, enabled, note})
	}
	return rows
}

// layout is the screen: header with the filter dropdown, table, detail box,
// buttons (or the form), status, and the confirm over them.
func (s servicesScreen) layout() *lipgloss.Compositor {
	title := titleStyle.Render("Services")
	if !s.loaded {
		return stack(title, "", "loading…")
	}
	if s.form != nil {
		hint := dimStyle.Render("restart: " + strings.Join(service.RestartPolicies, ", ") + " · user root only if typed explicitly")
		return stack(title, "", s.form.view(), "", hint, s.status)
	}
	which := "running·enabled·failed"
	if s.all {
		which = "all"
	}
	drop := "filter: [ " + which + " " + glyph("▾") + " ]"
	pad := max(s.w-ansi.StringWidth(title)-ansi.StringWidth(drop), 1)
	header := lipgloss.NewLayer(title+strings.Repeat(" ", pad), lipgloss.NewLayer(drop).ID("f").X(ansi.StringWidth(title)+pad))
	blocks := []any{header}
	if s.err != nil {
		blocks = append(blocks, "Services unreadable: "+s.err.Error())
	} else {
		blocks = append(blocks, s.table.layer(s.w))
		if unit := s.selected(); unit != "" {
			blocks = append(blocks, detailBox(unit, s.detail(unit), s.w, 3))
		}
	}
	bs := s.buttons()
	blocks = append(blocks, buttonRow(bs[:5]...), buttonRow(bs[5:]...))
	if s.status != "" {
		blocks = append(blocks, s.status)
	}
	c := stack(blocks...)
	if s.asking {
		c.AddLayers(s.ask.layer(s.w))
	}
	return c
}

func (s servicesScreen) View() tea.View { return tea.NewView(s.layout().Render()) }

// detail describes unit: description, override, and what the Lockout Guard disables.
func (s servicesScreen) detail(unit string) string {
	var desc string
	for _, svc := range s.list {
		if svc.Name == unit {
			desc = cmp.Or(svc.Description, "no description")
		}
	}
	lines := []string{desc, "vendor unit, no override"}
	if b, err := os.ReadFile(service.OverridePath(s.m.Root, unit)); err == nil {
		lines[1] = "vendor unit + override (" + service.OverridePath("", unit) + ", " +
			strconv.Itoa(strings.Count(strings.TrimRight(string(b), "\n"), "\n")+1) + " lines)"
	}
	var off []string
	why := ""
	for _, b := range s.buttons() {
		if b.why != "" && b.why != "no override to revert" {
			off, why = append(off, b.label), b.why
		}
	}
	if why != "" {
		why, _, _ = strings.Cut(why, ", cannot")
		lines = append(lines, warnStyle.Render(glyph("◆")+" "+strings.Join(off, ", ")+" disabled by the Lockout Guard: "+why))
	}
	return strings.Join(lines, "\n")
}
