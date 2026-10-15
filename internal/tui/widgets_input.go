package tui

// Input widgets (see widgets.go for the set): forms of text fields and the
// two-tier confirm dialogs. Both answer update with a formEvent.

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// formEvent is what a key did to a form or confirm.
type formEvent int

const (
	editing   formEvent = iota
	submitted           // enter on a form; yes on a confirm
	cancelled           // esc; no on a confirm
)

// form is a titled list of labelled text fields; tab/↑↓ move between them,
// enter submits, esc cancels. The screen validates on submitted and sets err
// to show the problem under the fields (cleared on the next edit).
// Placeholders: f.inputs[i].Placeholder = "…"; f.hints[i] is shown dim after
// field i. f.opts[i] makes field i a row of options (see options).
type form struct {
	title  string
	labels []string
	inputs []textinput.Model
	opts   []options
	hints  []string
	focus  int
	err    string
}

// options is a field's row of choices, ←/→ moving between them and space
// picking one: [x] toggles, or (●) exactly one of them when radio. With text
// the field's text input follows them and gets the typing; else it has none.
type options struct {
	names       []string
	on          []bool
	radio, text bool
	cur         int // the option under the cursor
}

func newForm(title string, labels ...string) form {
	f := form{title: title, labels: labels, opts: make([]options, len(labels)), hints: make([]string, len(labels))}
	for range labels {
		f.inputs = append(f.inputs, newInput())
	}
	f.inputs[0].Focus()
	return f
}

// value is what was typed into field i.
func (f form) value(i int) string { return f.inputs[i].Value() }

func (f form) update(msg tea.Msg) (form, formEvent) {
	if k, ok := msg.(tea.KeyPressMsg); ok {
		d := 0
		switch k.String() {
		case "enter":
			return f, submitted
		case "esc":
			return f, cancelled
		case "tab", "down":
			d = 1
		case "shift+tab", "up":
			d = len(f.inputs) - 1
		}
		if d != 0 {
			f.inputs[f.focus].Blur()
			f.focus = (f.focus + d) % len(f.inputs)
			f.inputs[f.focus].Focus()
			return f, editing
		}
		f.err = ""
		if o := &f.opts[f.focus]; o.names != nil {
			switch k.String() {
			case "left":
				o.cur = max(o.cur-1, 0)
				return f, editing
			case "right":
				o.cur = min(o.cur+1, len(o.names)-1)
				return f, editing
			case "space":
				if o.radio {
					clear(o.on)
				}
				o.on[o.cur] = !o.on[o.cur] || o.radio
				return f, editing
			}
			if !o.text {
				return f, editing
			}
		}
	}
	f.inputs[f.focus], _ = f.inputs[f.focus].Update(msg)
	return f, editing
}

func (f form) view() string {
	lw := 0
	for _, l := range f.labels {
		lw = max(lw, ansi.StringWidth(l))
	}
	var ls []string
	if f.title != "" {
		ls = append(ls, titleStyle.Render(f.title))
	}
	for i, l := range f.labels {
		in := f.inputs[i]
		if in.Width() == 0 && in.Value() == "" { // without a width bubbles shows a placeholder's first rune only
			in.SetWidth(ansi.StringWidth(in.Placeholder))
		}
		v := in.View()
		if o := f.opts[i]; o.names != nil {
			v = o.view(i == f.focus, v)
		}
		if f.hints[i] != "" {
			v += "   " + dimStyle.Render(f.hints[i])
		}
		ls = append(ls, " "+fit(l+":", lw+1)+" "+v)
	}
	if f.err != "" {
		ls = append(ls, " "+errStyle.Render(f.err))
	}
	return strings.Join(ls, "\n")
}

// view draws the options, the one under the cursor reversed while focused,
// then in, the text field's view, when o has one.
func (o options) view(focused bool, in string) string {
	var vs []string
	for i, n := range o.names {
		box := "[ ] "
		switch {
		case o.radio && o.on[i]:
			box = "(" + glyph("●") + ") "
		case o.radio:
			box = "( ) "
		case o.on[i]:
			box = "[x] "
		}
		if focused && i == o.cur {
			n = selectedStyle.Render(n)
		}
		vs = append(vs, box+n)
	}
	if o.text {
		vs = append(vs, in)
	}
	return strings.Join(vs, "  ")
}

func (f form) keys() string {
	if f.opts[f.focus].names != nil {
		return "←/→ choose · space pick · enter ok · tab next field · esc cancel"
	}
	if len(f.inputs) > 1 {
		return "enter ok · tab next field · esc cancel"
	}
	return "enter ok · esc cancel"
}

// confirm is a dialog over the screen. Normal (name == ""): [ Yes ] [ No ],
// y yes, n/esc/enter no. Dangerous: the target name must be typed exactly
// before enter (or [ verb ]) confirms; esc cancels.
type confirm struct {
	title, verb, name string
	input             textinput.Model
}

func newConfirm(title string) confirm { return confirm{title: title} }

func newDangerous(title, verb, name string) confirm {
	c := confirm{title: title, verb: verb, name: name, input: newInput()}
	c.input.Focus()
	return c
}

func (c confirm) typing() bool { return c.name != "" }

func (c confirm) keys() string {
	if c.name != "" {
		return "enter " + strings.ToLower(c.verb) + " · esc cancel"
	}
	return "y yes · n no"
}

func (c confirm) update(msg tea.Msg) (confirm, formEvent) {
	k, ok := msg.(tea.KeyPressMsg)
	switch {
	case c.name == "" && ok && k.String() == "y":
		return c, submitted
	case c.name == "" && ok && (k.String() == "n" || k.String() == "esc" || k.String() == "enter"):
		return c, cancelled
	case c.name == "":
	case ok && k.String() == "esc":
		return c, cancelled
	case ok && k.String() == "enter":
		if c.input.Value() == c.name {
			return c, submitted
		}
	default:
		c.input, _ = c.input.Update(msg)
	}
	return c, editing
}

// layer is the dialog centred over a screen w columns wide, above the
// screen's layers; clicks anywhere on it stay on it.
func (c confirm) layer(w int) *lipgloss.Layer {
	bs := []button{{"y", "Yes", ""}, {"n", "No", ""}}
	var body []string
	fw := 0 // the field line's width, with room for the name typed
	if c.name != "" {
		yes := button{"enter", c.verb, ""}
		if c.input.Value() != c.name {
			yes.why = "type the name"
		}
		bs = []button{yes, {"esc", "Cancel", ""}}
		prompt := fmt.Sprintf("Type %q to confirm: ", c.name)
		fw = ansi.StringWidth(prompt) + ansi.StringWidth(c.name) + 2
		body = append(body, prompt+c.input.View())
	}
	btns := buttonLayers(bs)
	bw := 0
	for _, b := range btns {
		bw = b.GetX() + b.Width()
	}
	boxW := max(ansi.StringWidth(c.title)+8, bw+8, fw+4, 32)
	body = append(body, "") // the buttons' line
	for _, b := range btns {
		b.X(b.GetX() + (boxW-bw)/2).Y(len(body)).Z(2)
	}
	box := detailBox(c.title, strings.Join(body, "\n"), boxW, len(body))
	return lipgloss.NewLayer(box, btns...).ID("dialog").X(max((w-boxW)/2, 0)).Y(2).Z(1)
}
