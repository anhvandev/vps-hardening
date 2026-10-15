package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/anhvandev/vpsctl/internal/firewall"
	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

func init() { screens["Overview"] = newOverview }

// overview is the read-only machine summary. It reads everything live when
// opened; a missing piece (fail2ban absent, firewall off) is a state, not an error.
type overview struct {
	m    *harden.Machine
	rows []row // nil while loading
}

type row struct{ label, value string }

type overviewMsg []row

func newOverview(m *harden.Machine) tea.Model { return overview{m: m} }

func (o overview) Init() tea.Cmd {
	return func() tea.Msg {
		rows := firewallRows(o.m)
		rows = append(rows,
			row{"fail2ban", fail2banState(o.m.R)},
			row{"Updates", updateState(o.m)},
			row{"Disk /", diskState(o.m.R)},
			row{"RAM", ramState(o.m.Root)})
		return overviewMsg(rows)
	}
}

func (o overview) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case overviewMsg:
		o.rows = msg
	case tea.KeyPressMsg:
		if msg.String() == "esc" {
			return o, Back
		}
	}
	return o, nil
}

func (o overview) View() tea.View {
	if o.rows == nil {
		return tea.NewView(titleStyle.Render("Overview") + "\n\nloading…")
	}
	var b strings.Builder
	b.WriteString(titleStyle.Render("Overview") + "\n")
	for _, r := range o.rows {
		fmt.Fprintf(&b, "\n%-10s %s", r.label, r.value)
	}
	return tea.NewView(b.String())
}

// firewallRows is the firewall state followed by one row per Firewall Rule.
func firewallRows(m *harden.Machine) []row {
	var res system.Result
	var err error
	var active bool
	switch m.Host.Family {
	case "debian":
		res, err = m.R.Run("ufw", "status")
		active = res.Code == 0 && strings.Contains(res.Stdout, "Status: active")
	case "rhel":
		res, err = m.R.Run("firewall-cmd", "--state")
		active = res.Code == 0
	default:
		return []row{{"Firewall", "not managed on this distro"}}
	}
	switch {
	case err != nil:
		return []row{{"Firewall", "not installed"}}
	case !active:
		// ufw still lists its rules while inactive; firewalld cannot.
		rows := []row{{"Firewall", "inactive"}}
		fw, _ := firewall.New(m.Host, m.R, m.Pkgs)
		if rules, err := fw.List(); err == nil {
			rows = append(rows, ruleRows(rules)...)
		}
		return rows
	}
	fw, _ := firewall.New(m.Host, m.R, m.Pkgs)
	rules, err := fw.List()
	if err != nil {
		return []row{{"Firewall", "active"}, {"", "  rules unreadable: " + err.Error()}}
	}
	return append([]row{{"Firewall", "active"}}, ruleRows(rules)...)
}

func ruleRows(rules []firewall.Rule) []row {
	if len(rules) == 0 {
		return []row{{"", "  no rules"}}
	}
	var rows []row
	for _, r := range rules {
		s := strconv.Itoa(r.Port)
		if r.End != 0 {
			s += fmt.Sprintf("-%d", r.End)
		}
		if r.Proto != "" {
			s += "/" + r.Proto
		}
		if r.From != "" {
			s += " from " + r.From
		}
		if r.Limit {
			s += " (rate-limited)"
		}
		rows = append(rows, row{"", "  " + s})
	}
	return rows
}

func fail2banState(r system.Runner) string {
	res, err := r.Run("fail2ban-client", "status")
	switch {
	case err != nil:
		return "not installed"
	case res.Code != 0:
		return "inactive"
	}
	for _, line := range strings.Split(res.Stdout, "\n") {
		if _, jails, ok := strings.Cut(line, "Jail list:"); ok && strings.TrimSpace(jails) != "" {
			return "active, jails: " + strings.TrimSpace(jails)
		}
	}
	return "active, no jails"
}

// updateState is: last automatic-update run, pending updates, reboot required.
func updateState(m *harden.Machine) string {
	timer, pending, reboot := "", "unknown", "reboot unknown"
	switch m.Host.Family {
	case "debian":
		timer = "apt-daily-upgrade.timer"
		if res, err := m.R.Run("apt-get", "-s", "-o", "Debug::NoLocking=true", "upgrade"); err == nil && res.Code == 0 {
			pending = strconv.Itoa(strings.Count("\n"+res.Stdout, "\nInst "))
		}
		reboot = "no reboot required"
		if _, err := os.Stat(filepath.Join(m.Root, "/var/run/reboot-required")); err == nil {
			reboot = "REBOOT REQUIRED"
		}
	case "rhel":
		timer = "dnf-automatic.timer"
		// -C: cached metadata only, no network round-trip.
		if res, err := m.R.Run("dnf", "-q", "-C", "check-update"); err == nil && (res.Code == 0 || res.Code == 100) {
			n := 0
			for _, line := range strings.Split(res.Stdout, "\n") {
				if strings.HasPrefix(line, "Obsoleting") {
					break
				}
				if len(strings.Fields(line)) == 3 {
					n++
				}
			}
			pending = strconv.Itoa(n)
		}
		if res, err := m.R.Run("needs-restarting", "-r"); err == nil && res.Code == 0 {
			reboot = "no reboot required"
		} else if err == nil && res.Code == 1 {
			reboot = "REBOOT REQUIRED"
		}
	}
	last := "unknown"
	if res, err := m.R.Run("systemctl", "show", "-p", "LastTriggerUSec", "--value", timer); timer != "" && err == nil && res.Code == 0 {
		last = strings.TrimSpace(res.Stdout)
		if last == "" || last == "n/a" {
			last = "never"
		}
	}
	return fmt.Sprintf("last run %s · %s pending · %s", last, pending, reboot)
}

func diskState(r system.Runner) string {
	res, err := r.Run("df", "-h", "-P", "/")
	if err != nil || res.Code != 0 {
		return "unknown"
	}
	lines := strings.Split(strings.TrimSpace(res.Stdout), "\n")
	if f := strings.Fields(lines[len(lines)-1]); len(f) >= 5 && len(lines) > 1 {
		return fmt.Sprintf("%s used of %s (%s)", f[2], f[1], f[4])
	}
	return "unknown"
}

func ramState(root string) string {
	b, err := os.ReadFile(filepath.Join(root, "/proc/meminfo"))
	if err != nil {
		return "unknown"
	}
	kb := map[string]float64{}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) >= 2 {
			kb[strings.TrimSuffix(f[0], ":")], _ = strconv.ParseFloat(f[1], 64)
		}
	}
	total, avail := kb["MemTotal"], kb["MemAvailable"]
	if total == 0 {
		return "unknown"
	}
	const gib = 1024 * 1024
	return fmt.Sprintf("%.1f GiB used of %.1f GiB", (total-avail)/gib, total/gib)
}
