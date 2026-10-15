package tui

import (
	"path/filepath"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/actionlog"
	"github.com/anhvandev/vpsctl/internal/cron"
	"github.com/anhvandev/vpsctl/internal/harden"
)

func init() { screens["Cron"] = newCron }

// cronScreen lists the Cron Entries of root and each Managed User, read live;
// a adds an entry for the user under the cursor, e edits and d deletes one.
type cronScreen struct {
	m      *harden.Machine
	rows   []cronRow // nil while loading
	err    error     // Managed Users unreadable
	cursor int
	mode   string // "", "add", "edit" or "delete"
	input  string
	status string // last save error, "" if none
}

// cronRow is a user's header (entry "") or one of their Cron Entries.
type cronRow struct {
	user, entry string
	err         error // header only: crontab unreadable
}

type cronMsg struct {
	rows []cronRow
	err  error
}

type cronSavedMsg struct{ err error }

func newCron(m *harden.Machine) tea.Model { return cronScreen{m: m} }

func (c cronScreen) Init() tea.Cmd {
	return func() tea.Msg {
		names := []string{"root"}
		users, err := c.m.ManagedUsers()
		for _, u := range users {
			names = append(names, u.Name)
		}
		var rows []cronRow
		for _, name := range names {
			entries, rerr := cron.Entries(c.m.R, name)
			rows = append(rows, cronRow{user: name, err: rerr})
			for _, e := range entries {
				rows = append(rows, cronRow{user: name, entry: e})
			}
		}
		return cronMsg{rows, err}
	}
}

func (c cronScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case cronMsg:
		c.rows, c.err = msg.rows, msg.err
		c.cursor = min(c.cursor, len(c.rows)-1)
	case cronSavedMsg:
		if msg.err != nil {
			c.status = msg.err.Error()
			return c, nil
		}
		c.mode, c.input, c.status = "", "", ""
		return c, c.Init()
	case tea.KeyPressMsg:
		if c.rows == nil {
			if msg.String() == "esc" {
				return c, Back
			}
			return c, nil
		}
		return c.key(msg)
	}
	return c, nil
}

func (c cronScreen) key(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	row := c.rows[c.cursor]
	switch c.mode {
	case "add", "edit":
		switch msg.String() {
		case "esc":
			c.mode, c.input, c.status = "", "", ""
		case "backspace":
			if c.input != "" {
				c.input = c.input[:len(c.input)-1]
			}
		case "enter":
			if err := cron.Validate(c.input); err != nil {
				c.status = err.Error()
				return c, nil
			}
			return c, c.save(c.mode, row.user, row.entry, c.input)
		default:
			c.input += msg.Text
		}
		return c, nil
	case "delete":
		if msg.String() == "y" {
			return c, c.save("delete", row.user, row.entry, "")
		}
		c.mode = ""
		return c, nil
	}
	switch msg.String() {
	case "esc":
		return c, Back
	case "up", "k":
		c.cursor = max(c.cursor-1, 0)
	case "down", "j":
		c.cursor = min(c.cursor+1, len(c.rows)-1)
	case "a":
		c.mode, c.input, c.status = "add", "", ""
	case "e", "enter":
		if row.entry != "" {
			c.mode, c.input, c.status = "edit", row.entry, ""
		}
	case "d":
		if row.entry != "" {
			c.mode, c.status = "delete", ""
		}
	}
	return c, nil
}

// save swaps old for new in user's crontab under the global lock and logs it.
// The action log gets only the verb and user: commands may carry secrets.
func (c cronScreen) save(verb, user, old, new string) tea.Cmd {
	if verb == "add" {
		old = ""
	}
	return func() tea.Msg {
		lk, err := actionlog.Lock(filepath.Join(c.m.Root, actionlog.LockPath))
		if err != nil {
			return cronSavedMsg{err}
		}
		defer lk.Close()
		err = cron.Replace(c.m.R, user, old, new)
		result := "ok"
		if err != nil {
			result = "failed"
		}
		actionlog.Append(filepath.Join(c.m.Root, actionlog.LogPath), "cron "+verb+" "+user, result) // failures to log are ignored
		return cronSavedMsg{err}
	}
}

func (c cronScreen) View() tea.View {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Cron") + "\n\n")
	if c.rows == nil {
		return tea.NewView(b.String() + "loading…")
	}
	if c.err != nil {
		b.WriteString("Managed Users unreadable: " + c.err.Error() + "\n")
	}
	for i, r := range c.rows {
		mark := "  "
		if i == c.cursor {
			mark = "> "
		}
		switch {
		case r.entry != "":
			b.WriteString(mark + "    " + r.entry + "\n")
		case r.err != nil:
			b.WriteString(mark + r.user + "  crontab unreadable: " + r.err.Error() + "\n")
		default:
			b.WriteString(mark + r.user + "\n")
		}
	}
	b.WriteString("\n")
	switch c.mode {
	case "add":
		b.WriteString("new entry for " + c.rows[c.cursor].user + ": " + c.input + "█\n")
	case "edit":
		b.WriteString("edit entry: " + c.input + "█\n")
	case "delete":
		b.WriteString("delete this entry? y/n\n")
	default:
		b.WriteString(dimStyle.Render("a add · e edit · d delete"))
	}
	if c.status != "" {
		b.WriteString(c.status)
	}
	return tea.NewView(strings.TrimRight(b.String(), "\n"))
}
