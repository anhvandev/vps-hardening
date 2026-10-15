package tui

import (
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/exp/teatest/v2"
)

// confirmScreen is a stand-in screen 60 columns wide showing only a confirm
// and the answer it got.
type confirmScreen struct {
	c   confirm
	got formEvent
}

func (s confirmScreen) Init() tea.Cmd { return nil }

func (s confirmScreen) layout() *lipgloss.Compositor {
	return stack(strings.Repeat(" ", 60) + "\n\n\n\n\n").AddLayers(s.c.layer(60))
}

func (s confirmScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyPressMsg); ok && k.String() == "ctrl+c" {
		return s, tea.Quit
	}
	if m, ok := msg.(tea.MouseClickMsg); ok {
		if msg = mouse(s.layout(), m); msg == nil {
			return s, nil
		}
	}
	if s.got == editing {
		s.c, s.got = s.c.update(msg)
	}
	return s, nil
}

func (s confirmScreen) View() tea.View {
	return tea.NewView(s.layout().Render() + "\nanswer: " + []string{"none", "confirmed", "cancelled"}[s.got])
}

// answer drives a dangerous "Delete user bob" confirm with do and returns
// its last frame.
func answer(t *testing.T, do func(tm *teatest.TestModel)) string {
	t.Helper()
	tm := teatest.NewTestModel(t, confirmScreen{c: newDangerous("Delete user bob", "Delete", "bob")}, teatest.WithInitialTermSize(80, 24))
	do(tm)
	tm.Send(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	return ansi.Strip(tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second)).View().Content)
}

// [ Delete ] sits on the dialog's third line, from column 18.
var deleteButton = tea.MouseClickMsg{X: 20, Y: 4, Button: tea.MouseLeft}

// A dangerous confirm acts only once the exact name is typed; enter and
// [ Delete ] do nothing before that.
func TestDangerousConfirmWantsExactName(t *testing.T) {
	v := answer(t, func(tm *teatest.TestModel) {
		tm.Type("bo")
		tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
		tm.Send(deleteButton)
		tm.Type("bx")
		tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	})
	wantAll(t, v, `Type "bob" to confirm: bobx`, "[ Delete ]  [ Cancel ]", "answer: none")

	v = answer(t, func(tm *teatest.TestModel) {
		tm.Type("bob")
		tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	})
	wantAll(t, v, "answer: confirmed")

	v = answer(t, func(tm *teatest.TestModel) {
		tm.Type("bob")
		tm.Send(deleteButton)
	})
	wantAll(t, v, "answer: confirmed")

	v = answer(t, func(tm *teatest.TestModel) {
		tm.Type("bob")
		tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape})
	})
	wantAll(t, v, "answer: cancelled")
}
