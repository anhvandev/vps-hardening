package tui

import (
	"fmt"
	"io"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/anhvandev/vpsctl/internal/cron"
	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

func init() { screens["Cron"] = newCron }

// cronScreen lists the Cron Entries of root and each Managed User, read live;
// a adds an entry for the selected user, e edits and d deletes (after a
// Yes/No) the selected one, each as a Task.
type cronScreen struct {
	m      *harden.Machine
	rows   []cronRow // nil while loading
	err    error     // Managed Users unreadable
	table  table
	mode   string // "", "add" or "edit": the form is up
	form   form
	asking bool // the delete confirm is up
	ask    confirm
	target cronRow // the row the form or confirm acts on
	w, h   int
}

// cronRow is one Cron Entry, or a user with none (entry "") whose crontab
// may be unreadable (err).
type cronRow struct {
	user, entry string
	err         error
}

type cronMsg struct {
	rows []cronRow
	err  error
}

func newCron(m *harden.Machine) tea.Model {
	return cronScreen{m: m, table: newTable("USER", "ENTRY")}
}

func (c cronScreen) Init() tea.Cmd {
	return func() tea.Msg {
		names := []string{"root"}
		users, err := c.m.ManagedUsers()
		for _, u := range users {
			names = append(names, u.Name)
		}
		rows := []cronRow{}
		for _, name := range names {
			entries, rerr := cron.Entries(c.m.R, name)
			if rerr != nil || len(entries) == 0 {
				rows = append(rows, cronRow{user: name, err: rerr})
			}
			for _, e := range entries {
				rows = append(rows, cronRow{user: name, entry: e})
			}
		}
		return cronMsg{rows, err}
	}
}

func (c cronScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		c.w, c.h = msg.Width, msg.Height
		c.table.height = max(c.h-8, 3) // room for the header and buttons or form
		c.table.setRows(c.table.rows)
		return c, nil
	case cronMsg:
		c.rows, c.err = msg.rows, msg.err
		c.table.setRows(c.tableRows())
		return c, nil
	case taskDoneMsg:
		return c, c.Init()
	case tea.MouseClickMsg:
		if m := mouse(c.layout(), msg); m != nil {
			return c.Update(m)
		}
		return c, nil
	}
	switch {
	case c.rows == nil:
		if k, ok := msg.(tea.KeyPressMsg); ok && k.String() == "esc" {
			return c, Back
		}
		return c, nil
	case c.mode != "":
		return c.formUpdate(msg)
	case c.asking:
		a, ev := c.ask.update(msg)
		c.ask, c.asking = a, ev == editing
		if ev == submitted {
			return c, c.save("delete", c.target, "")
		}
		return c, nil
	}
	if t, ok := c.table.update(msg); ok {
		c.table = t
		return c, nil
	}
	k, ok := msg.(tea.KeyPressMsg)
	if !ok || disabled(c.buttons(), k.String()) {
		return c, nil
	}
	row := c.selected()
	switch k.String() {
	case "esc":
		return c, Back
	case "a":
		c.mode, c.target, c.form = "add", row, newForm("Add a Cron Entry for "+row.user, "Entry")
		c.form.inputs[0].Placeholder = "MIN HOUR DOM MON DOW command, or @daily command"
	case "e", "enter":
		if row.entry != "" {
			c.mode, c.target, c.form = "edit", row, newForm("Edit a Cron Entry of "+row.user, "Entry")
			c.form.inputs[0].SetValue(row.entry)
		}
	case "d":
		c.target, c.asking, c.ask = row, true, newConfirm("Delete this Cron Entry of "+row.user+"?")
	case "r":
		return c, c.Init()
	}
	return c, nil
}

// formUpdate edits the add/edit form; enter validates, then saves.
func (c cronScreen) formUpdate(msg tea.Msg) (tea.Model, tea.Cmd) {
	fm, ev := c.form.update(msg)
	c.form = fm
	switch ev {
	case cancelled:
		c.mode = ""
	case submitted:
		if err := cron.Validate(c.form.value(0)); err != nil {
			c.form.err = err.Error()
			return c, nil
		}
		verb := c.mode
		c.mode = ""
		return c, c.save(verb, c.target, c.form.value(0))
	}
	return c, nil
}

// selected is the selected row; the zero row when none.
func (c cronScreen) selected() cronRow {
	if i := c.table.selected(); i >= 0 {
		return c.rows[i]
	}
	return cronRow{user: "root"}
}

// save swaps row's entry for new in its user's crontab as a Task. The
// entries stay out of the Task's output and Task History (they may carry
// secrets): the crontab commands bypass the Task's runner and errors are
// quiet; the Task is named by the verb and user only.
func (c cronScreen) save(verb string, row cronRow, new string) tea.Cmd {
	old := row.entry
	if verb == "add" {
		old = ""
	}
	what := map[string]string{"add": " a Cron Entry for ", "edit": " a Cron Entry of ", "delete": " a Cron Entry of "}[verb] + row.user
	done := map[string]string{"add": "added", "edit": "edited", "delete": "deleted"}[verb]
	return runTask(strings.ToUpper(verb[:1])+verb[1:]+what, "cron "+verb+" "+row.user, done+what,
		taskStep{"Install " + row.user + "'s crontab", func(system.Runner, io.Writer) error {
			if err := cron.Replace(c.m.R, row.user, old, new); err != nil {
				return quiet{err}
			}
			return nil
		}})
}

func (c cronScreen) typing() bool {
	return c.mode != "" || c.table.typing()
}

func (c cronScreen) keys() string {
	switch {
	case c.mode != "":
		return c.form.keys()
	case c.asking:
		return c.ask.keys()
	case c.table.typing():
		return c.table.keys()
	}
	return c.table.keys() + " · " + keyHelp(c.buttons()) + " · esc back"
}

func (c cronScreen) buttons() []button {
	ed := "no Cron Entry selected"
	if c.selected().entry != "" {
		ed = ""
	}
	return []button{{"a", "+ Add", ""}, {"e", "Edit", ed}, {"d", "Delete", ed}, {"r", "Refresh", ""}}
}

func (c cronScreen) tableRows() [][]string {
	var rows [][]string
	for _, r := range c.rows {
		switch {
		case r.err != nil:
			rows = append(rows, []string{r.user, errStyle.Render("crontab unreadable: " + r.err.Error())})
		case r.entry == "":
			rows = append(rows, []string{r.user, naStyle.Render("no entries")})
		default:
			rows = append(rows, []string{r.user, r.entry})
		}
	}
	return rows
}

func (c cronScreen) layout() *lipgloss.Compositor {
	title := titleStyle.Render("Cron")
	if c.rows == nil {
		return stack(title, "", "loading…")
	}
	n := 0
	for _, r := range c.rows {
		if r.entry != "" {
			n++
		}
	}
	summary := fmt.Sprintf("%d entries", n)
	blocks := []any{title + strings.Repeat(" ", max(c.w-ansi.StringWidth(title)-ansi.StringWidth(summary), 1)) + summary}
	if c.err != nil {
		blocks = append(blocks, "Managed Users unreadable: "+c.err.Error())
	}
	blocks = append(blocks, c.table.layer(c.w))
	if c.mode != "" {
		blocks = append(blocks, "", c.form.view())
	} else {
		blocks = append(blocks, buttonRow(c.buttons()...))
	}
	l := stack(blocks...)
	if c.asking {
		l.AddLayers(c.ask.layer(c.w))
	}
	return l
}

func (c cronScreen) View() tea.View { return tea.NewView(c.layout().Render()) }
