package tui

// Shared widgets every screen is built from (design.md §0, §4, §10):
//
//	table      rows selected with ↑↓/jk, a click or the wheel; / filters (widgets_table.go).
//	           t := newTable("PORT", "PROTO"); t.height = rows shown;
//	           t.setRows(rows); t, ok = t.update(msg) (ok: t used msg);
//	           t.selected() is the index into rows, -1 for none.
//	detailBox  detailBox(title, body, w, lines): the box under a table for the selected row.
//	button     button{key, label, why}: an action bound to one shared key
//	           (a add · d delete · e edit · r refresh …). why != "" disables
//	           it: drawn grey, its key and clicks do nothing. why is the
//	           Lockout Guard reason; show it in the detail box, never a dialog.
//	           buttonRow(bs...) draws them; disabled(bs, key) tells Update to
//	           ignore key; keyHelp(bs) lists them for the status bar.
//	form       newForm(title, labels...): labelled text fields (widgets_input.go).
//	confirm    newConfirm(title) asks [ Yes ] [ No ]; newDangerous(title,
//	           verb, name) wants name typed exactly (widgets_input.go).
//
// Layout and mouse: a screen builds its view as stack(blocks...), a lipgloss
// Compositor of strings and widget layers placed top to bottom (a confirm is
// added on top with c.AddLayers(confirm.layer(w))), and View renders it. The
// shell sends the open screen mouse messages in screen-local cells and a
// tea.WindowSizeMsg with the screen's size. On a click, Update rebuilds the
// same layout and calls mouse(layout, msg): a row becomes a rowMsg (give it
// to the table), a button its key press, so Update handles clicks as keys.
// Hit ids: "row:N" for table rows, the key for buttons.
//
// Two optional screen methods the shell asks: keys() string, the screen's
// keys for the status bar; typing() bool, true while a text field has focus
// (otherwise ?, m and tab go to the shell, not the screen).

import (
	"strconv"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// detailBox is the rounded box titled title holding body wrapped to w
// columns, padded to lines body lines (so the layout below it stays put).
func detailBox(title, body string, w, lines int) string {
	w = max(w, 8) // a screen not sized yet
	bd := lipgloss.RoundedBorder()
	if ascii {
		bd = lipgloss.ASCIIBorder()
	}
	top := bd.TopLeft + bd.Top + " " + titleStyle.Render(title) + " "
	top = ansi.Truncate(top, w-1, "") + strings.Repeat(bd.Top, max(w-1-ansi.StringWidth(top), 0)) + bd.TopRight
	ls := strings.Split(lipgloss.NewStyle().Width(w-4).Render(body), "\n")
	out := []string{top}
	for i := range max(lines, len(ls)) {
		l := ""
		if i < len(ls) {
			l = ls[i]
		}
		out = append(out, bd.Left+" "+fit(l, w-4)+" "+bd.Right)
	}
	return strings.Join(append(out, bd.BottomLeft+strings.Repeat(bd.Bottom, w-2)+bd.BottomRight), "\n")
}

// button is an action bound to key; why != "" disables it and says why.
type button struct{ key, label, why string }

// buttonLayers draws bs on one line from column 0; enabled ones hit as their key.
func buttonLayers(bs []button) []*lipgloss.Layer {
	var ls []*lipgloss.Layer
	x := 0
	for _, b := range bs {
		s := "[ " + b.label + " ]"
		l := lipgloss.NewLayer(s).ID(b.key)
		if b.why != "" {
			l = lipgloss.NewLayer(naStyle.Render(s))
		}
		ls = append(ls, l.X(x))
		x += ansi.StringWidth(s) + 2
	}
	return ls
}

// buttonRow is the screen's button line.
func buttonRow(bs ...button) *lipgloss.Layer {
	return lipgloss.NewLayer("", buttonLayers(bs)...).X(1)
}

// disabled reports whether key belongs to a disabled button of bs.
func disabled(bs []button, key string) bool {
	for _, b := range bs {
		if b.key == key && b.why != "" {
			return true
		}
	}
	return false
}

// keyHelp is "a open port · d remove …" for the status bar.
func keyHelp(bs []button) string {
	var ks []string
	for _, b := range bs {
		ks = append(ks, b.key+" "+strings.ToLower(strings.TrimPrefix(b.label, "+ ")))
	}
	return strings.Join(ks, " · ")
}

// stack places blocks (strings or *lipgloss.Layer) top to bottom; "" is a
// blank line.
func stack(blocks ...any) *lipgloss.Compositor {
	var ls []*lipgloss.Layer
	y := 0
	for _, b := range blocks {
		l, ok := b.(*lipgloss.Layer)
		if !ok {
			s := b.(string)
			if s == "" {
				s = " "
			}
			l = lipgloss.NewLayer(s)
		}
		ls = append(ls, l.Y(y))
		y += max(l.Height(), 1)
	}
	return lipgloss.NewCompositor(ls...)
}

// mouse is what a screen-local click on layout c means: rowMsg for a table
// row, the key press of an enabled button, nil for anything else.
func mouse(c *lipgloss.Compositor, msg tea.MouseClickMsg) tea.Msg {
	if msg.Button != tea.MouseLeft {
		return nil
	}
	id := c.Hit(msg.X, msg.Y).ID()
	if n, ok := strings.CutPrefix(id, "row:"); ok {
		i, _ := strconv.Atoi(n)
		return rowMsg(i)
	}
	switch r := []rune(id); {
	case id == "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case id == "esc":
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	case len(r) == 1:
		return tea.KeyPressMsg{Code: r[0], Text: id}
	}
	return nil
}

// newInput is a text field without prompt or blinking (no timer to run).
func newInput() textinput.Model {
	in := textinput.New()
	in.Prompt = ""
	s := in.Styles()
	s.Cursor.Blink = false
	in.SetStyles(s)
	return in
}
