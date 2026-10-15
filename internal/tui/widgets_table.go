package tui

// The table widget (see widgets.go for the set).

import (
	"strconv"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// table is a list of rows with a header, drawn in a box.
type table struct {
	head      []string
	rows      [][]string
	height    int // rows shown at most; 0 = all
	cursor    int // selected row among the shown (filtered) ones
	top       int // first row shown
	filter    textinput.Model
	filtering bool // the filter field has focus
}

// rowMsg is a click on the table's row N (among the shown ones).
type rowMsg int

func newTable(head ...string) table { return table{head: head, filter: newInput()} }

// setRows replaces the rows, keeping the selection where it was.
func (t *table) setRows(rows [][]string) {
	t.rows = rows
	t.keepCursor()
}

// shown is the index of every row matching the filter.
func (t table) shown() []int {
	q := strings.ToLower(t.filter.Value())
	var is []int
	for i, r := range t.rows {
		if strings.Contains(strings.ToLower(ansi.Strip(strings.Join(r, " "))), q) {
			is = append(is, i)
		}
	}
	return is
}

// selected is the index into rows of the selected row, -1 for none.
func (t table) selected() int {
	if is := t.shown(); t.cursor < len(is) {
		return is[t.cursor]
	}
	return -1
}

func (t table) typing() bool { return t.filtering }

// keys is the table's part of the status bar.
func (t table) keys() string {
	if t.filtering {
		return "enter keep filter · esc clear"
	}
	return "↑↓ move · / filter"
}

// update moves the selection (↑↓/jk, rowMsg, wheel) and edits the filter
// (/ opens it, enter keeps it, esc clears it). ok is false when msg is not
// the table's, e.g. esc with no filter set.
func (t table) update(msg tea.Msg) (table, bool) {
	switch msg := msg.(type) {
	case rowMsg:
		t.cursor = int(msg)
	case tea.MouseWheelMsg:
		switch msg.Button {
		case tea.MouseWheelDown:
			t.top += 3
		case tea.MouseWheelUp:
			t.top -= 3
		default:
			return t, false
		}
		t.keepTop()
		return t, true
	case tea.KeyPressMsg:
		if t.filtering {
			switch msg.String() {
			case "enter":
				t.filtering = false
				t.filter.Blur()
			case "esc":
				t.filtering = false
				t.filter.Blur()
				t.filter.Reset()
			default:
				t.filter, _ = t.filter.Update(msg)
				t.cursor, t.top = 0, 0
			}
			break
		}
		switch msg.String() {
		case "up", "k":
			t.cursor--
		case "down", "j":
			t.cursor++
		case "/":
			t.filtering = true
			t.filter.Focus()
		case "esc":
			if t.filter.Value() == "" {
				return t, false
			}
			t.filter.Reset()
		default:
			return t, false
		}
	default:
		return t, false
	}
	t.keepCursor()
	return t, true
}

// rowsShown is how many rows fit.
func (t table) rowsShown(n int) int {
	if t.height > 0 && t.height < n {
		return t.height
	}
	return n
}

// keepCursor clamps the selection and scrolls it into view.
func (t *table) keepCursor() {
	n := len(t.shown())
	t.cursor = max(min(t.cursor, n-1), 0)
	h := t.rowsShown(n)
	t.top = max(min(t.top, t.cursor, n-h), t.cursor-max(h, 1)+1, 0)
}

// keepTop clamps the scroll and keeps the selection on a shown row.
func (t *table) keepTop() {
	n := len(t.shown())
	h := t.rowsShown(n)
	t.top = max(min(t.top, n-h), 0)
	t.cursor = max(min(t.cursor, t.top+h-1), t.top)
}

// layer draws the table w columns wide: filter line (when set), box,
// header, then the shown rows, each hit as "row:N".
func (t table) layer(w int) *lipgloss.Layer {
	w = max(w, 8) // a screen not sized yet
	bd := border()
	var ls []*lipgloss.Layer
	line := func(s, id string) { ls = append(ls, lipgloss.NewLayer(s).ID(id).Y(len(ls))) }
	if t.filtering || t.filter.Value() != "" {
		line("/ "+t.filter.View(), "")
	}
	widths := make([]int, len(t.head))
	for _, r := range append([][]string{t.head}, t.rows...) {
		for i, c := range r {
			widths[i] = max(widths[i], ansi.StringWidth(c))
		}
	}
	cells := func(r []string) string {
		var b strings.Builder
		for i, c := range r {
			if i < len(r)-1 {
				c = fit(c, widths[i]) + "  "
			}
			b.WriteString(c)
		}
		return b.String()
	}
	row := func(s string) string { return bd.Left + fit(s, w-2) + bd.Right }
	line(bd.TopLeft+strings.Repeat(bd.Top, w-2)+bd.TopRight, "")
	line(row(" "+dimStyle.Render(cells(t.head))), "")
	shown := t.shown()
	for i := t.top; i < t.top+t.rowsShown(len(shown)); i++ {
		mark := " "
		if i == t.cursor {
			mark = lipgloss.NewStyle().Foreground(accent).Render(glyph("▌"))
		}
		line(row(mark+cells(t.rows[shown[i]])), "row:"+strconv.Itoa(i))
	}
	if len(shown) == 0 {
		line(row(" "+dimStyle.Render("nothing to show")), "")
	}
	line(bd.BottomLeft+strings.Repeat(bd.Bottom, w-2)+bd.BottomRight, "")
	return lipgloss.NewLayer("", ls...)
}
