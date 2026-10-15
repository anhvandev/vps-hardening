package tui

import (
	"fmt"
	"strings"
	"text/tabwriter"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/service"
)

func init() { screens["Services"] = newServices }

// serviceRows bounds how many Services are drawn; the list scrolls with the cursor.
const serviceRows = 20

// servicesScreen lists Services read live: running, enabled or failed ones by
// default, all with a; / types a name filter. s/x/r/e/d start, stop, restart,
// enable and disable the selected Service (Protected Units refused); E edits
// its override in $EDITOR, U reverts it (services_edit.go).
type servicesScreen struct {
	m         *harden.Machine
	loaded    bool
	list      []service.Service
	err       error // list unreadable
	all       bool
	filter    string
	filtering bool // typing into the filter
	cursor    int  // index into shown()
	status    string
	edit      *unitEdit // override being edited, nil if none
}

// servicesMsg is one read of the Services, plus the outcome of the last action.
type servicesMsg struct {
	list   []service.Service
	err    error
	status string
}

func newServices(m *harden.Machine) tea.Model { return servicesScreen{m: m} }

func (s servicesScreen) Init() tea.Cmd { return s.reload("") }

func (s servicesScreen) reload(status string) tea.Cmd {
	return func() tea.Msg {
		list, err := service.List(s.m.R)
		return servicesMsg{list, err, status}
	}
}

// shown is the list narrowed by the all toggle and the name filter.
func (s servicesScreen) shown() []service.Service {
	var out []service.Service
	for _, svc := range s.list {
		notable := svc.Sub == "running" || svc.Enabled == "enabled" || svc.Active == "failed"
		if (s.all || notable) && strings.Contains(strings.ToLower(svc.Name), strings.ToLower(s.filter)) {
			out = append(out, svc)
		}
	}
	return out
}

// actionKeys maps a key to its systemctl verb and what to say once done.
var actionKeys = map[string][2]string{
	"s": {"start", "started"}, "x": {"stop", "stopped"}, "r": {"restart", "restarted"},
	"e": {"enable", "enabled"}, "d": {"disable", "disabled"},
}

func (s servicesScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if s, cmd, ok := s.editUpdate(msg); ok {
		return s, cmd
	}
	switch msg := msg.(type) {
	case servicesMsg:
		s.list, s.err, s.status, s.loaded = msg.list, msg.err, msg.status, true
		s.cursor = max(min(s.cursor, len(s.shown())-1), 0)
	case tea.KeyPressMsg:
		if s.filtering {
			switch msg.String() {
			case "esc", "enter":
				s.filtering = false
			case "backspace":
				if r := []rune(s.filter); len(r) > 0 {
					s.filter = string(r[:len(r)-1])
				}
			default:
				s.filter += msg.Text
			}
			s.cursor = 0
			return s, nil
		}
		key := msg.String()
		switch key {
		case "esc":
			return s, Back
		case "up", "k":
			s.cursor = max(s.cursor-1, 0)
		case "down", "j":
			s.cursor = max(min(s.cursor+1, len(s.shown())-1), 0)
		case "a":
			s.all, s.cursor = !s.all, 0
		case "/":
			s.filtering = true
		}
		if a, ok := actionKeys[key]; ok && s.cursor < len(s.shown()) {
			return s, s.act(a[0], a[1], s.shown()[s.cursor].Name)
		}
	}
	return s, nil
}

// act runs verb on unit through logMutation, then re-reads the Services and
// reports the unit's resulting state, or the refusal or systemctl error.
func (s servicesScreen) act(verb, done, unit string) tea.Cmd {
	return func() tea.Msg {
		err := logMutation(s.m.Root, "service "+verb+" "+unit, func() error {
			return service.Do(s.m.R, verb, unit)
		})
		list, lerr := service.List(s.m.R)
		status := done + " " + unit
		if err != nil {
			status = err.Error()
		}
		for _, svc := range list {
			if err == nil && svc.Name == unit {
				status += ": " + state(svc) + ", " + or(svc.Enabled, "no unit file")
			}
		}
		return servicesMsg{list, lerr, status}
	}
}

func state(svc service.Service) string { return svc.Active + " (" + svc.Sub + ")" }

func (s servicesScreen) View() tea.View {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Services") + "\n\n")
	if !s.loaded {
		return tea.NewView(b.String() + "loading…")
	}
	which := "running/enabled/failed"
	if s.all {
		which = "all"
	}
	cursor := ""
	if s.filtering {
		cursor = "█"
	}
	fmt.Fprintf(&b, "filter: %s%s  %s\n\n", s.filter, cursor, dimStyle.Render("showing "+which))
	shown := s.shown()
	switch {
	case s.err != nil:
		b.WriteString("Services unreadable: " + s.err.Error())
	case len(shown) == 0:
		b.WriteString("no matching Services")
	default:
		first := max(s.cursor-serviceRows+1, 0)
		var table strings.Builder
		tw := tabwriter.NewWriter(&table, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "Service\tState\tEnabled\tDescription")
		for _, svc := range shown[first:min(first+serviceRows, len(shown))] {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", svc.Name, state(svc), or(svc.Enabled, "-"), svc.Description)
		}
		tw.Flush()
		lines := strings.Split(table.String(), "\n")
		lines[s.cursor-first+1] = selectedStyle.Render(lines[s.cursor-first+1])
		b.WriteString(strings.Join(lines, "\n"))
		if len(shown) > serviceRows {
			fmt.Fprintf(&b, "%s\n", dimStyle.Render(fmt.Sprintf("%d of %d", s.cursor+1, len(shown))))
		}
	}
	b.WriteString("\n\n" + dimStyle.Render("s start · x stop · r restart · e enable · d disable · E edit · U revert · a all · / filter") + "\n")
	if s.status != "" {
		b.WriteString("\n" + s.status)
	}
	return tea.NewView(strings.TrimRight(b.String(), "\n"))
}
