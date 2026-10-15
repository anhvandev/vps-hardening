package tui

// The Overview's cards (overview.go), each read live from the host.

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/service"
	"github.com/anhvandev/vpsctl/internal/updates"
)

// line is "label  value" with the labels of a card aligned.
func line(label, value string, to openMsg) cardLine {
	return cardLine{fmt.Sprintf("%-11s %s", label, value), to}
}

func okText(s string) string   { return okStyle.Render(glyph("●")) + " " + s }
func warnText(s string) string { return warnStyle.Render(glyph("⚠")) + " " + s }
func badText(s string) string  { return errStyle.Render(glyph("✗")) + " " + s }

// security: Hardening x/y and what's missing, SSH, Firewall, Docker, Logins.
func (o overview) security() card {
	m := o.m
	rec, _ := harden.LoadRecord(m.Root)
	var done, chosen int
	var keyOnly bool
	var port string
	var missing []string
	for _, s := range m.Status(rec) {
		switch {
		case s.ID == "ssh":
			keyOnly = s.State == harden.Done
		case s.ID == "port" && s.State == harden.Done:
			port = " · :" + s.Detail
		}
		if s.State != harden.Skipped {
			chosen++
		}
		if s.State == harden.Done {
			done++
		}
		if s.State == harden.Missing {
			missing = append(missing, s.Name)
		}
	}
	badge := fmt.Sprintf("%d/%d", done, chosen)
	if len(missing) > 0 {
		badge += "  missing: " + strings.Join(missing, ", ")
	}
	ssh := okText("key-only" + port)
	switch {
	case !keyOnly:
		badge, ssh = badText(badge), badText("not key-only"+port)
	case done < chosen:
		badge = warnText(badge)
	default:
		badge = okText(badge)
	}

	fw := firewallName(m)
	state, rules, err := firewallRules(m)
	switch {
	case state == "active" && err != nil:
		fw = okText(fw + " · rules unreadable")
	case state == "active":
		fw = okText(fmt.Sprintf("%s · %d rule%s", fw, len(rules), plural(len(rules))))
	case state == "inactive":
		fw = badText(fw + " inactive")
	default:
		fw = naStyle.Render(glyph("·")) + " " + state
	}
	return card{"Security", openMsg{title: "Hardening"}, []cardLine{
		line("Hardening", badge, openMsg{}),
		line("SSH", ssh, openMsg{title: "SSH"}),
		line("Firewall", fw, openMsg{title: "Firewall"}),
		line("Docker", dockerState(m.R), openMsg{title: "Docker"}),
		line("Logins 24h", loginsSummary(m), openMsg{title: "Logins"}),
	}}
}

// resources: CPU, RAM, Swap, Disk / and uptime, all from /proc and df.
func (o overview) resources(prev cpuTimes) (_ card, swapNone bool, cpu cpuTimes) {
	root := o.m.Root
	cpuText := "unknown"
	if cpu = readCPU(root); cpu.total > 0 {
		d := cpuTimes{cpu.busy - prev.busy, cpu.total - prev.total}
		if prev.total == 0 || d.total <= 0 {
			d = cpu
		}
		cpuText = fmt.Sprintf("%s  %.0f%%", bar(d.busy/d.total), 100*d.busy/d.total)
		if b, err := os.ReadFile(filepath.Join(root, "/proc/loadavg")); err == nil && len(strings.Fields(string(b))) > 0 {
			cpuText += "  load " + strings.Fields(string(b))[0]
		}
	}

	ram := "unknown"
	if used, total := readRAM(root); total > 0 {
		const gib = 1024 * 1024
		ram = fmt.Sprintf("%s  %.1f/%.1f GiB", bar(used/total), used/gib, total/gib)
	}

	swap := swapState(root)
	swapNone = swap == "none"
	if swapNone {
		swap = naStyle.Render(glyph("·")) + " none   [ Create swap ]"
	}

	disk := "unknown"
	if res, err := o.m.R.Run("df", "-h", "-P", "/"); err == nil && res.Code == 0 {
		ls := strings.Split(strings.TrimSpace(res.Stdout), "\n")
		if f := strings.Fields(ls[len(ls)-1]); len(f) >= 5 && len(ls) > 1 {
			pct, _ := strconv.Atoi(strings.TrimSuffix(f[4], "%"))
			disk = fmt.Sprintf("%s  %s/%s  %s", bar(float64(pct)/100), f[2], f[1], f[4])
			if pct >= 80 {
				disk += "  " + warnStyle.Render(glyph("⚠"))
			}
		}
	}

	up := "unknown"
	if b, err := os.ReadFile(filepath.Join(root, "/proc/uptime")); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if s, err := strconv.ParseFloat(f[0], 64); err == nil {
				up = span(time.Duration(s) * time.Second)
			}
		}
	}
	return card{"Resources", openMsg{}, []cardLine{
		line("CPU", cpuText, openMsg{}),
		line("RAM", ram, openMsg{}),
		line("Swap", swap, openMsg{title: "Swap"}),
		line("Disk /", disk, openMsg{title: "Disk"}),
		line("Uptime", up, openMsg{}),
	}}, swapNone, cpu
}

// readCPU is the aggregate "cpu" line of /proc/stat; idle counts iowait.
func readCPU(root string) cpuTimes {
	b, err := os.ReadFile(filepath.Join(root, "/proc/stat"))
	if err != nil {
		return cpuTimes{}
	}
	first, _, _ := strings.Cut(string(b), "\n")
	f := strings.Fields(first)
	if len(f) < 6 || f[0] != "cpu" {
		return cpuTimes{}
	}
	var t cpuTimes
	for i, s := range f[1:] {
		v, _ := strconv.ParseFloat(s, 64)
		t.total += v
		if i != 3 && i != 4 { // idle, iowait
			t.busy += v
		}
	}
	return t
}

// readRAM is used (total − available) and total memory in KiB.
func readRAM(root string) (used, total float64) {
	b, err := os.ReadFile(filepath.Join(root, "/proc/meminfo"))
	if err != nil {
		return 0, 0
	}
	kb := map[string]float64{}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) >= 2 {
			kb[strings.TrimSuffix(f[0], ":")], _ = strconv.ParseFloat(f[1], 64)
		}
	}
	return kb["MemTotal"] - kb["MemAvailable"], kb["MemTotal"]
}

// updatesEvery is how often the Overview lists the pending updates (a
// simulated upgrade, heavy on a small machine); the rest refreshes every 5 s.
const updatesEvery = 10 * time.Minute

// updates: pending security and other updates, the last automatic run,
// reboot. pending is the pending line as last listed, "" to list it now.
func (o overview) updates(now time.Time, pending string) (card, string) {
	m := o.m
	if pending == "" {
		pending = "pending updates unknown"
		if ps, err := updates.List(m.R, m.Host.PkgManager); err == nil {
			sec := 0
			for _, p := range ps {
				if p.Security {
					sec++
				}
			}
			pending = fmt.Sprintf("%d security · %d other pending", sec, len(ps)-sec)
			if sec > 0 {
				pending = warnText(pending)
			} else {
				pending = okText(pending)
			}
		}
	}

	last := "last auto-run unknown"
	timer := map[string]string{"debian": "apt-daily-upgrade.timer", "rhel": "dnf-automatic.timer"}[m.Host.Family]
	if res, err := m.R.Run("systemctl", "show", "-p", "LastTriggerUSec", "--value", timer); timer != "" && err == nil && res.Code == 0 {
		s := strings.TrimSpace(res.Stdout)
		switch t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", s); {
		case s == "" || s == "n/a":
			last = "last auto-run never"
		case err == nil:
			last = "last auto-run " + span(now.Sub(t)) + " ago"
		default:
			last = "last auto-run " + s
		}
	}

	reboot := okText("no reboot required")
	switch needed, known, _ := updates.RebootNeeded(m.R, m.Root, m.Host.PkgManager); {
	case needed:
		reboot = warnText("reboot required")
	case !known:
		reboot = "reboot unknown"
	}
	return card{"Updates", openMsg{title: "Updates"}, []cardLine{{pending, openMsg{}}, {last, openMsg{}}, {reboot, openMsg{}}}}, pending
}

// failedShown bounds the failed Services named one per line.
const failedShown = 3

// services: running count, failed Services by name and Timers whose
// Service failed on its last run.
func (o overview) services() card {
	c := card{"Services", openMsg{title: "Services"}, nil}
	list, err := service.List(o.m.R)
	if err != nil {
		c.lines = []cardLine{{"Services unknown", openMsg{}}}
		return c
	}
	running := 0
	failed := map[string]bool{}
	var names []string
	for _, s := range list {
		if s.Sub == "running" {
			running++
		}
		if s.Active == "failed" {
			failed[s.Name] = true
			names = append(names, s.Name)
		}
	}
	c.lines = append(c.lines, cardLine{okText(fmt.Sprintf("%d running", running)), openMsg{}})
	for i, n := range names {
		if i == failedShown {
			c.lines = append(c.lines, cardLine{badText(fmt.Sprintf("%d more failed", len(names)-i)), openMsg{}})
			break
		}
		c.lines = append(c.lines, cardLine{badText("failed: " + n), openMsg{"Services", n}})
	}
	timers, _ := service.ListTimers(o.m.R)
	var missed []string
	for _, t := range timers {
		if failed[t.Service] {
			missed = append(missed, t.Name)
		}
	}
	if len(missed) > 0 {
		c.lines = append(c.lines, cardLine{warnText(fmt.Sprintf("%d Timer%s missed last run", len(missed), plural(len(missed)))),
			openMsg{"Timers", missed[0]}})
	}
	return c
}

// bar is frac (0..1) as ten cells.
func bar(frac float64) string {
	full, empty := "▇", "▁"
	if ascii.Load() {
		full, empty = "#", "-"
	}
	n := min(max(int(frac*10+0.5), 0), 10)
	return strings.Repeat(full, n) + strings.Repeat(empty, 10-n)
}

// span is d as "12d 4h", "3h 5m", "7m" or "4s".
func span(d time.Duration) string {
	d = max(d, 0)
	switch h := int(d.Hours()); {
	case h >= 24:
		return fmt.Sprintf("%dd %dh", h/24, h%24)
	case h >= 1:
		return fmt.Sprintf("%dh %dm", h, int(d.Minutes())%60)
	case d >= time.Minute:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}
