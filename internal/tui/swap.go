package tui

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/swap"
	"github.com/anhvandev/vpsctl/internal/system"
)

func init() { screens["Swap"] = newSwap }

// swapScreen lists the active swap (files and partitions) and the RAM. a
// creates vpsctl's own swapfile (size suggested = RAM, max 4 GiB), e resizes
// it, d removes it after the path is typed; all run as Tasks after a
// confirm. Swap vpsctl didn't create is read-only. Remove and resize are
// disabled, with the reason, while the swap in use wouldn't fit in the free
// RAM; a size the disk can't hold is refused in the form. The swap package
// checks both again under the lock.
type swapScreen struct {
	m      *harden.Machine
	loaded bool
	sw     swapMsg
	table  table
	sizing bool // the size form is up
	resize bool // ... for a resize, not a create
	form   form
	asking bool // the confirm is up
	ask    confirm
	run    tea.Cmd // the Task a yes starts
	w, h   int
}

type swapMsg struct {
	s       swap.State
	err     error // swap or RAM unreadable
	free    int64 // free disk on /
	freeErr error
}

func newSwap(m *harden.Machine) tea.Model {
	return swapScreen{m: m, table: newTable("NAME", "TYPE", "SIZE", "USED", "NOTE")}
}

func (s swapScreen) Init() tea.Cmd {
	return func() tea.Msg {
		var msg swapMsg
		msg.s, msg.err = swap.Read(s.m.Root)
		msg.free, msg.freeErr = swap.FreeDisk(s.m.R)
		return msg
	}
}

func (s swapScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		s.w, s.h = msg.Width, msg.Height
		s.table.height = max(s.h-12, 3)
		s.table.setRows(s.table.rows)
		return s, nil
	case swapMsg:
		s.sw, s.loaded = msg, true
		var rows [][]string
		for _, a := range msg.s.Areas {
			note := "read-only"
			if a.Name == swap.File {
				note = "vpsctl"
			}
			rows = append(rows, []string{a.Name, a.Type, swap.Human(a.Size), swap.Human(a.Used), note})
		}
		s.table.setRows(rows)
		return s, nil
	case taskDoneMsg:
		return s, s.Init()
	case tea.MouseClickMsg:
		if m := mouse(s.layout(), msg); m != nil {
			return s.Update(m)
		}
		return s, nil
	}
	switch {
	case s.sizing:
		return s.formUpdate(msg)
	case s.asking:
		c, ev := s.ask.update(msg)
		s.ask, s.asking = c, ev == editing
		if ev == submitted {
			return s, s.run
		}
		return s, nil
	}
	if t, ok := s.table.update(msg); ok {
		s.table = t
		return s, nil
	}
	k, ok := msg.(tea.KeyPressMsg)
	if !ok || !s.loaded || disabled(s.buttons(), k.String()) {
		return s, nil
	}
	switch k.String() {
	case "esc":
		return s, Back
	case "a", "e":
		s.sizing, s.resize = true, k.String() == "e"
		size, title := s.sw.s.Suggested(), "Create swapfile"
		if own, _ := s.sw.s.Own(); s.resize {
			size, title = own.Size, "Resize swapfile"
		}
		s.form = newForm(title, "Size (GiB)")
		s.form.inputs[0].SetValue(strconv.FormatInt(max(size>>30, 1), 10))
	case "d":
		s.asking, s.ask = true, newDangerous("Remove swapfile "+swap.File, "Remove", swap.File)
		s.run = runTask("Remove swapfile", "swap remove", "removed swapfile", s.step("Remove "+swap.File, func(r system.Runner) error {
			return swap.Remove(r, s.m.Root)
		}))
	case "r":
		return s, s.Init()
	}
	return s, nil
}

// formUpdate edits the size; enter checks it fits on the disk, then confirms.
func (s swapScreen) formUpdate(msg tea.Msg) (tea.Model, tea.Cmd) {
	fm, ev := s.form.update(msg)
	s.form, s.sizing = fm, ev == editing
	if ev != submitted {
		return s, nil
	}
	gib, err := strconv.ParseInt(strings.TrimSpace(s.form.value(0)), 10, 64)
	if err != nil || gib < 1 || gib > 1024 {
		s.form.err, s.sizing = "want a whole number of GiB, e.g. 2", true
		return s, nil
	}
	size, h := gib<<30, swap.Human(gib<<30)
	free := s.sw.free
	if own, ok := s.sw.s.Own(); ok && s.resize {
		free += own.Size // the old file's space comes back
	}
	if err := swap.DiskRefusal(free, size); err != nil && s.sw.freeErr == nil {
		s.form.err, s.sizing = err.Error(), true
		return s, nil
	}
	s.asking = true
	if s.resize {
		s.ask = newConfirm("Resize the swapfile to " + h + "?")
		s.run = runTask("Resize swapfile", "swap resize "+h, "resized swapfile to "+h, s.step("Resize "+swap.File, func(r system.Runner) error {
			return swap.Resize(r, s.m.Root, size)
		}))
	} else {
		s.ask = newConfirm("Create a " + h + " swapfile?")
		s.run = runTask("Create swapfile", "swap create "+h, "created "+h+" swapfile", s.step("Create "+swap.File, func(r system.Runner) error {
			return swap.Create(r, s.m.Root, size)
		}))
	}
	return s, nil
}

// step is a Task step running do; its commands go to the Task's output.
func (s swapScreen) step(name string, do func(system.Runner) error) taskStep {
	return taskStep{name, func(r system.Runner, _ io.Writer) error { return do(r) }}
}

func (s swapScreen) typing() bool {
	return s.sizing || s.table.typing() || s.asking && s.ask.typing()
}

func (s swapScreen) keys() string {
	switch {
	case s.sizing:
		return s.form.keys()
	case s.asking:
		return s.ask.keys()
	case s.table.typing():
		return s.table.keys()
	}
	return s.table.keys() + " · " + keyHelp(s.buttons()) + " · esc back"
}

// offRefusal is why resize and remove are disabled, "" if they aren't.
func (s swapScreen) offRefusal() string {
	if err := s.sw.s.OffRefusal(); err != nil {
		return strings.TrimPrefix(err.Error(), "refused: ")
	}
	return ""
}

func (s swapScreen) buttons() []button {
	create := button{"a", "+ Create swapfile", ""}
	if _, ok := s.sw.s.Own(); ok {
		create.why = "vpsctl's swapfile exists; resize it"
	}
	if s.sw.err != nil {
		create.why = "swap unreadable"
	}
	why := s.offRefusal()
	return []button{create, {"e", "Resize", why}, {"d", "Remove", why}, {"r", "Refresh", ""}}
}

// layout is the screen: header, swap table, buttons (or the size form), the
// reason resize/remove are disabled, and the confirm over them.
func (s swapScreen) layout() *lipgloss.Compositor {
	if !s.loaded {
		return stack(titleStyle.Render("Swap"), "", "loading…")
	}
	title := titleStyle.Render("Swap")
	blocks := []any{title}
	if s.sw.err != nil {
		blocks = append(blocks, "swap unreadable: "+s.sw.err.Error())
	} else {
		total := int64(0)
		for _, a := range s.sw.s.Areas {
			total += a.Size
		}
		summary := "none"
		if total > 0 {
			summary = swap.Human(total)
		}
		summary += fmt.Sprintf(" · RAM %s · free RAM %s", swap.Human(s.sw.s.RAM), swap.Human(s.sw.s.Available))
		blocks[0] = title + strings.Repeat(" ", max(s.w-ansi.StringWidth(title)-ansi.StringWidth(summary), 1)) + summary
		if len(s.sw.s.Areas) > 0 {
			blocks = append(blocks, s.table.layer(s.w))
		}
	}
	if s.sizing {
		blocks = append(blocks, "", s.form.view(), dimStyle.Render(" (suggested = RAM, max 4 GiB)"))
	} else {
		blocks = append(blocks, buttonRow(s.buttons()...))
	}
	if _, own := s.sw.s.Own(); own && s.offRefusal() != "" {
		blocks = append(blocks, warnStyle.Render(glyph("⚠")+" Resize and Remove disabled: "+s.offRefusal()))
	}
	c := stack(blocks...)
	if s.asking {
		c.AddLayers(s.ask.layer(s.w))
	}
	return c
}

func (s swapScreen) View() tea.View { return tea.NewView(s.layout().Render()) }

// swapState is the Overview's Swap line: "none", or the total and its use.
func swapState(root string) string {
	st, err := swap.Read(root)
	if err != nil {
		return "unknown"
	}
	var size, used int64
	for _, a := range st.Areas {
		size, used = size+a.Size, used+a.Used
	}
	if size == 0 {
		return "none"
	}
	return fmt.Sprintf("%s used of %s", swap.Human(used), swap.Human(size))
}
