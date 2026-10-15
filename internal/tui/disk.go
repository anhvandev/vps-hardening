package tui

import (
	"cmp"
	"fmt"
	"io"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/anhvandev/vpsctl/internal/disk"
	"github.com/anhvandev/vpsctl/internal/docker"
	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

func init() { screens["Disk"] = newDisk }

const (
	journalKeepMB = 200 // the journal vacuum's target size
	largestShown  = 8   // directories listed by a scan
)

// cleanups are the Cleanup rows, in order; key N runs row N. Add a cleanup
// by appending it here (disk.Cleanup: name, reclaimable bytes, Run).
func cleanups(m *harden.Machine) []disk.Cleanup {
	cs := []disk.Cleanup{
		disk.Journal(m.R, journalKeepMB),
		disk.PackageCache(m.R, m.Root, m.Host.PkgManager),
		disk.OldKernels(m.R, m.Host.PkgManager),
	}
	if docker.Installed(m.R) {
		cs = append(cs, disk.DanglingImages(m.R))
	}
	return cs
}

// diskScreen shows usage per filesystem, the largest directories under the
// selected one (s scans, c cancels the scan), and the fixed cleanups, each
// run as a Task after a confirm (dangerous for old kernels). Nothing here
// deletes an arbitrary file or directory.
type diskScreen struct {
	m       *harden.Machine
	loaded  bool
	data    diskMsg
	table   table // filesystems
	scan    io.ReadCloser
	scanned string // the mount scanned or being scanned
	dirs    []disk.Dir
	state   string // the scan's state: "scanning…", "scan cancelled", an error
	asking  bool
	ask     confirm
	target  disk.Cleanup
	w, h    int
}

type diskMsg struct {
	fss      []disk.Filesystem
	err      error
	cleanups []disk.Cleanup
}

// scanMsg is a scan's end; it is stale (and ignored) unless scan is current.
type scanMsg struct {
	scan io.ReadCloser
	dirs []disk.Dir
	err  error
}

func newDisk(m *harden.Machine) tea.Model {
	return diskScreen{m: m, table: newTable("MOUNT", "USAGE", "USED", "USE%")}
}

func (d diskScreen) Init() tea.Cmd {
	return func() tea.Msg {
		fss, err := disk.Filesystems(d.m.R)
		return diskMsg{fss, err, cleanups(d.m)}
	}
}

func (d diskScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		d.w, d.h = msg.Width, msg.Height
		d.table.height = max(d.h-24, 1) // room for the scan box, buttons and cleanups
		d.table.setRows(d.table.rows)
		return d, nil
	case diskMsg:
		d.data, d.loaded = msg, true
		d.table.setRows(d.rows())
		return d, nil
	case scanMsg:
		if msg.scan == d.scan && d.scan != nil {
			d.scan.Close()
			d.scan, d.dirs, d.state = nil, msg.dirs, ""
			if msg.err != nil {
				d.state = "scan failed: " + msg.err.Error()
			}
		}
		return d, nil
	case taskDoneMsg:
		return d, d.Init()
	case tea.MouseClickMsg:
		if m := mouse(d.layout(), msg); m != nil {
			return d.Update(m)
		}
		return d, nil
	}
	if d.asking {
		c, ev := d.ask.update(msg)
		d.ask, d.asking = c, ev == editing
		if ev == submitted {
			return d, d.run(d.target)
		}
		return d, nil
	}
	if t, ok := d.table.update(msg); ok {
		d.table = t
		return d, nil
	}
	k, ok := msg.(tea.KeyPressMsg)
	if !ok || disabled(d.buttons(), k.String()) {
		return d, nil
	}
	switch k.String() {
	case "esc":
		return d.cancel(""), Back
	case "s":
		return d.startScan()
	case "c":
		return d.cancel("scan cancelled"), nil
	case "r":
		return d, d.Init()
	}
	if n, err := strconv.Atoi(k.String()); err == nil && n >= 1 && n <= len(d.data.cleanups) {
		c := d.data.cleanups[n-1]
		if d.why(c) != "" {
			return d, nil
		}
		d.target, d.asking = c, true
		d.ask = newConfirm(c.Name + "?")
		if c.Dangerous {
			w := strings.Fields(c.Name)
			d.ask = newDangerous(c.Name+" "+c.Detail, w[0], strings.ToLower(w[len(w)-1]))
		}
	}
	return d, nil
}

// startScan measures the directories under the selected filesystem in the
// background; its result comes back as a scanMsg.
func (d diskScreen) startScan() (tea.Model, tea.Cmd) {
	mount := d.data.fss[d.table.selected()].Mount
	rc, err := disk.Scan(d.m.R, mount)
	d.scanned, d.dirs = mount, nil
	if err != nil {
		d.state = "scan failed: " + err.Error()
		return d, nil
	}
	d.scan, d.state = rc, "scanning…"
	return d, func() tea.Msg {
		dirs, err := disk.Largest(rc, mount, largestShown)
		return scanMsg{rc, dirs, err}
	}
}

// cancel stops a running scan (killing du), noting state.
// ponytail: leaving through the sidebar doesn't cancel; du runs to its end.
func (d diskScreen) cancel(state string) diskScreen {
	if d.scan != nil {
		d.scan.Close()
		d.scan, d.state = nil, state
	}
	return d
}

// run runs c as a Task.
func (d diskScreen) run(c disk.Cleanup) tea.Cmd {
	return runTask(c.Name, "disk "+c.Name, "reclaimed up to "+size(c.Reclaimable),
		taskStep{c.Name, func(r system.Runner, _ io.Writer) error { return c.Run(r) }})
}

// why is the reason c can't run, "" when it can.
func (d diskScreen) why(c disk.Cleanup) string {
	if c.Why == "" && c.Reclaimable == 0 {
		return "nothing to reclaim"
	}
	return c.Why
}

func (d diskScreen) buttons() []button {
	scan := button{"s", "Scan", ""}
	switch {
	case d.scan != nil:
		scan.why = "scan running"
	case d.table.selected() < 0:
		scan.why = "no filesystem selected"
	}
	stop := button{"c", "Cancel", ""}
	if d.scan == nil {
		stop.why = "no scan running"
	}
	return []button{scan, stop, {"r", "Refresh", ""}}
}

func (d diskScreen) typing() bool { return d.table.typing() || d.asking && d.ask.typing() }

func (d diskScreen) keys() string {
	switch {
	case d.asking:
		return d.ask.keys()
	case d.table.typing():
		return d.table.keys()
	}
	return d.table.keys() + " · " + keyHelp(d.buttons()) + fmt.Sprintf(" · 1-%d run cleanup · esc back", len(d.data.cleanups))
}

// rows are the filesystem table rows with a usage bar; 80% full and up warns.
func (d diskScreen) rows() [][]string {
	full, empty := "▇", "▁"
	if ascii.Load() {
		full, empty = "#", "-"
	}
	var rows [][]string
	for _, fs := range d.data.fss {
		pct := 0
		if fs.Size > 0 {
			pct = int(fs.Used * 100 / fs.Size)
		}
		use := strconv.Itoa(pct) + "%"
		if pct >= 80 {
			use = warnStyle.Render(use + " " + glyph("⚠"))
		}
		bar := strings.Repeat(full, (pct+5)/10) + strings.Repeat(empty, 10-(pct+5)/10)
		rows = append(rows, []string{fs.Mount, bar, size(fs.Used) + " / " + size(fs.Size), use})
	}
	return rows
}

// layout is the screen: title, filesystems, the scan box, buttons, the
// cleanups, and the confirm over them.
func (d diskScreen) layout() *lipgloss.Compositor {
	if !d.loaded {
		return stack(titleStyle.Render("Disk"), "", "loading…")
	}
	blocks := []any{titleStyle.Render("Disk")}
	if d.data.err != nil {
		blocks = append(blocks, "filesystems unreadable: "+d.data.err.Error())
	} else {
		blocks = append(blocks, d.table.layer(d.w))
	}
	title := "Largest directories"
	body := dimStyle.Render("s scans the selected filesystem")
	if d.scanned != "" {
		title = fmt.Sprintf("Largest under %s (depth %d)", d.scanned, disk.ScanDepth)
		var ls []string
		for _, dir := range d.dirs {
			ls = append(ls, fmt.Sprintf("%9s  %s", size(dir.Size), dir.Path))
		}
		body = strings.Join(ls, "\n")
	}
	if d.state != "" {
		title += " · " + d.state
	}
	blocks = append(blocks, detailBox(title, body, d.w, largestShown), buttonRow(d.buttons()...), "")
	nameW := 0
	for _, c := range d.data.cleanups {
		nameW = max(nameW, ansi.StringWidth(c.Name))
	}
	blocks = append(blocks, titleStyle.Render(fit("Cleanup", nameW+4))+dimStyle.Render("reclaimable"))
	for i, c := range d.data.cleanups {
		why, reclaim := d.why(c), size(c.Reclaimable)
		if c.Why != "" {
			reclaim = naStyle.Render("n/a")
		}
		line := " " + fit(c.Name, nameW+3) + fit(reclaim, 12)
		btn := buttonLayers([]button{{strconv.Itoa(i + 1), "Run", why}})[0]
		note := cmp.Or(why, c.Detail)
		if why != "" {
			note = naStyle.Render(note)
		}
		x := ansi.StringWidth(line)
		blocks = append(blocks, lipgloss.NewLayer(line+strings.Repeat(" ", btn.Width()+2)+note, btn.X(x)))
	}
	c := stack(blocks...)
	if d.asking {
		c.AddLayers(d.ask.layer(d.w))
	}
	return c
}

func (d diskScreen) View() tea.View { return tea.NewView(d.layout().Render()) }

// size is b bytes in decimal units: "8 B", "614.4 MB", "1.4 GB".
func size(b int64) string {
	if b < 1000 {
		return fmt.Sprintf("%d B", b)
	}
	f, units := float64(b), "kMGTP"
	i := -1
	for f >= 1000 && i < len(units)-1 {
		f, i = f/1000, i+1
	}
	return fmt.Sprintf("%.1f %cB", f, units[i])
}
