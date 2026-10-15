package tui

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/logins"
)

func init() { screens["Logins"] = newLogins }

// loginsScreen lists the SSH logins and failed attempts of the last 24 h
// (w: 7 days), newest first, with the top failing IPs and the operator's own
// session marked. Read-only: no ban action here.
type loginsScreen struct {
	m      *harden.Machine
	window time.Duration
	loaded bool
	ls     loginsMsg
	table  table
	w, h   int
}

type loginsMsg struct {
	window time.Duration // the window read, to drop a stale read after w
	logins []logins.Login
	err    error
	own    []string // the operator's SSH_CONNECTION, nil if none
}

func newLogins(m *harden.Machine) tea.Model {
	return loginsScreen{m: m, window: logins.Day, table: newTable("TIME", "USER", "FROM", "RESULT")}
}

func (l loginsScreen) Init() tea.Cmd {
	return func() tea.Msg {
		ls, err := logins.Read(l.m.R, l.m.Root, l.window, time.Now())
		return loginsMsg{l.window, ls, err, sshConnection(l.m.Root)}
	}
}

func (l loginsScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		l.w, l.h = msg.Width, msg.Height
		l.table.height = max(l.h-6, 3) // room for the header and buttons
		l.table.setRows(l.table.rows)
		return l, nil
	case loginsMsg:
		if msg.window == l.window {
			l.ls, l.loaded = msg, true
			l.table.setRows(l.rows())
		}
		return l, nil
	case tea.MouseClickMsg:
		if m := mouse(l.layout(), msg); m != nil {
			return l.Update(m)
		}
		return l, nil
	}
	if t, ok := l.table.update(msg); ok {
		l.table = t
		return l, nil
	}
	k, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return l, nil
	}
	switch k.String() {
	case "esc":
		return l, Back
	case "w":
		l.window = map[time.Duration]time.Duration{logins.Day: logins.Week, logins.Week: logins.Day}[l.window]
		return l, l.Init()
	case "r":
		return l, l.Init()
	}
	return l, nil
}

func (l loginsScreen) typing() bool { return l.table.typing() }

func (l loginsScreen) keys() string {
	if l.table.typing() {
		return l.table.keys()
	}
	return l.table.keys() + " · " + keyHelp(l.buttons()) + " · esc back"
}

func (l loginsScreen) buttons() []button {
	other := map[time.Duration]string{logins.Day: "7 days", logins.Week: "24 hours"}[l.window]
	return []button{{"w", "Show " + other, ""}, {"r", "Refresh", ""}}
}

// rows are the table rows, one per connection; the operator's own is marked.
func (l loginsScreen) rows() [][]string {
	var rows [][]string
	for _, x := range l.ls.logins {
		result := errStyle.Render(glyph("✗") + " fail")
		if x.OK {
			result = okStyle.Render(glyph("●") + " ok")
			if len(l.ls.own) > 1 && l.ls.own[0] == x.IP && l.ls.own[1] == x.Port {
				result += dimStyle.Render(" · this session")
			}
		}
		rows = append(rows, []string{x.Time.Format("Jan 02 15:04"), x.User, x.IP, result})
	}
	return rows
}

// counts is how many connections logged in and how many failed.
func counts(ls []logins.Login) (ok, failed int) {
	for _, x := range ls {
		if x.OK {
			ok++
		} else {
			failed++
		}
	}
	return ok, failed
}

// topFailing is "IP  N" for the n source IPs with the most failed connections.
func topFailing(ls []logins.Login, n int) []string {
	by := map[string]int{}
	for _, x := range ls {
		if !x.OK {
			by[x.IP]++
		}
	}
	ips := make([]string, 0, len(by))
	for ip := range by {
		ips = append(ips, ip)
	}
	slices.SortFunc(ips, func(a, b string) int { return cmp.Or(by[b]-by[a], strings.Compare(a, b)) })
	var out []string
	for _, ip := range ips[:min(n, len(ips))] {
		out = append(out, fmt.Sprintf("%s  %d", ip, by[ip]))
	}
	return out
}

// layout is the screen: header with the window, logins table with the top
// failing IPs at its right, buttons.
func (l loginsScreen) layout() *lipgloss.Compositor {
	radio := func(d time.Duration, s string) string {
		if d == l.window {
			return "(" + glyph("●") + ") " + s
		}
		return "( ) " + s
	}
	title := titleStyle.Render("Logins") + "   window: " + radio(logins.Day, "24h") + " " + radio(logins.Week, "7d")
	if !l.loaded {
		return stack(title, "", "loading…")
	}
	if l.ls.err != nil {
		return stack(title, "", "logins unreadable: "+l.ls.err.Error(), "", buttonRow(l.buttons()...))
	}
	ok, failed := counts(l.ls.logins)
	summary := fmt.Sprintf("%d ok · %d failed", ok, failed)
	header := title + strings.Repeat(" ", max(l.w-ansi.StringWidth(title)-ansi.StringWidth(summary), 1)) + summary
	const side = 28 // the top failing IPs column
	top := append([]string{titleStyle.Render("Top failing IPs")}, topFailing(l.ls.logins, 5)...)
	if failed == 0 {
		top = append(top, dimStyle.Render("none"))
	}
	c := stack(header, l.table.layer(l.w-side), buttonRow(l.buttons()...))
	c.AddLayers(lipgloss.NewLayer(strings.Join(top, "\n")).X(l.w - side + 2).Y(2))
	return c
}

func (l loginsScreen) View() tea.View { return tea.NewView(l.layout().Render()) }

// loginsSummary is the Overview line: "N ok · M failed" in the last 24 h.
func loginsSummary(m *harden.Machine) string {
	ls, err := logins.Read(m.R, m.Root, logins.Day, time.Now())
	if err != nil {
		return "unknown"
	}
	ok, failed := counts(ls)
	return fmt.Sprintf("%d ok · %d failed", ok, failed)
}
