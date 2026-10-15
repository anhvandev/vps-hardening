package tui

import (
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/anhvandev/vpsctl/internal/harden"
)

func init() { screens["Overview"] = newOverview }

// overview is machine health as four cards (design §1): Security, Resources,
// Updates and Services, read live when opened and again on every refreshMsg
// while shown; the shell's tick moves "refreshed Ns ago". A missing piece (fail2ban absent,
// no updates info) is a state, not an error. Every card and line is a link:
// a click opens its screen, or the exact item (a failed Service).
type overview struct {
	m       *harden.Machine
	w       int
	cards   []card // nil while loading
	swap    bool   // no swap: offer [ Create swap ]
	cpu     cpuTimes
	at, now time.Time // the last read; the shell's clock
	loading bool
}

// card is a titled box; to is where a click on it leads (title "" = nowhere).
type card struct {
	title string
	to    openMsg
	lines []cardLine
}

// cardLine is one line of a card; a zero to falls back to the card's.
type cardLine struct {
	text string
	to   openMsg
}

// cpuTimes is /proc/stat's busy and total CPU time; CPU % is the busy share
// since the previous read (since boot on the first).
type cpuTimes struct{ busy, total float64 }

type overviewMsg struct {
	cards []card
	swap  bool
	cpu   cpuTimes
	at    time.Time
}

func newOverview(m *harden.Machine) tea.Model { return overview{m: m, loading: true} }

func (o overview) Init() tea.Cmd { return o.load() }

func (o overview) load() tea.Cmd {
	prev := o.cpu
	return func() tea.Msg {
		at := time.Now()
		res, swapNone, cpu := o.resources(prev)
		return overviewMsg{[]card{o.security(), res, o.updates(at), o.services()}, swapNone, cpu, at}
	}
}

func (o overview) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		o.w = msg.Width
	case overviewMsg:
		o.cards, o.swap, o.cpu, o.at, o.loading = msg.cards, msg.swap, msg.cpu, msg.at, false
		if o.now.Before(o.at) {
			o.now = o.at
		}
	case tickMsg:
		if msg.now.After(o.now) { // the clock never runs back
			o.now = msg.now
		}
	case refreshMsg:
		if !o.loading { // a slow read is not stacked on
			o.loading = true
			return o, o.load()
		}
	case tea.MouseClickMsg:
		if m := mouse(o.layout(), msg); m != nil {
			return o.Update(m)
		}
	case rowMsg:
		c := o.cards[int(msg)/100]
		to := c.to
		if i := int(msg)%100 - 1; i >= 0 && c.lines[i].to.title != "" {
			to = c.lines[i].to
		}
		if to.title != "" {
			return o, func() tea.Msg { return to }
		}
	case tea.KeyPressMsg:
		switch {
		case msg.String() == "esc":
			return o, Back
		case msg.String() == "s" && o.swap:
			return o, func() tea.Msg { return openMsg{title: "Swap"} }
		}
	}
	return o, nil
}

func (o overview) View() tea.View { return tea.NewView(o.layout().Render()) }

// layout is the title line and the cards two per row. Hit ids: "row:N" with
// N = card*100 for a card, card*100 + line + 1 for its lines.
func (o overview) layout() *lipgloss.Compositor {
	title := titleStyle.Render("Overview")
	if o.cards == nil {
		return stack(title, "", "loading…")
	}
	ago := dimStyle.Render("refreshed " + span(o.now.Sub(o.at)) + " ago")
	title += strings.Repeat(" ", max(o.w-ansi.StringWidth(title)-ansi.StringWidth(ago), 2)) + ago
	cw := max((o.w-1)/2, 20)
	blocks := []any{title, ""}
	for i := 0; i < len(o.cards); i += 2 {
		row := lipgloss.NewLayer("")
		h := max(len(o.cards[i].lines), len(o.cards[i+1].lines))
		for j := range 2 {
			row.AddLayers(o.cardLayer(i+j, cw, h).X(j * (cw + 1)))
		}
		blocks = append(blocks, row)
	}
	return stack(blocks...)
}

// cardLayer is card i drawn w wide with h lines, each line its own hit area.
func (o overview) cardLayer(i, w, h int) *lipgloss.Layer {
	c := o.cards[i]
	var body []string
	var ls []*lipgloss.Layer
	for j, l := range c.lines {
		s := fit(l.text, w-4)
		body = append(body, s)
		ls = append(ls, lipgloss.NewLayer(s).X(2).Y(1+j).ID("row:"+strconv.Itoa(i*100+j+1)))
	}
	return lipgloss.NewLayer(detailBox(c.title, strings.Join(body, "\n"), w, h), ls...).ID("row:" + strconv.Itoa(i*100))
}

func (o overview) buttons() []button { return []button{{"s", "Create swap", ""}} }

func (o overview) keys() string {
	if o.swap {
		return keyHelp(o.buttons()) + " · esc back"
	}
	return "esc back"
}
