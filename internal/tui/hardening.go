package tui

import (
	"io"
	"slices"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

func init() { screens["Hardening"] = newHardening }

// The wizard's fields (design §2b), in the form's order.
const (
	fUser = iota
	fPort
	fKey   // show once (option 0) or save to file (option 1, the path typed)
	fSteps // the optional steps, unchecked = skipped
	fRotate
)

// skipFlags are the `vpsctl harden` flags of fSteps's options, unchecked.
var skipFlags = []string{"--skip-firewall", "--skip-fail2ban", "--skip-updates", "--skip-sysctl"}

// hardening is the Hardening screen. On a machine whose SSH is key-only it
// is the Hardening Status (hardening_status.go); otherwise the wizard: the
// inputs of `vpsctl harden`, checked by the same harden.ParseFlags, then
// Hardening as a Task whose steps are the Hardening Steps, with the Verify
// Gate in its panel and the private key shown raw outside the TUI
// (rawKeyMachine) or written to the key file.
type hardening struct {
	m       *harden.Machine
	loaded  bool           // the Hardening Status was read
	steps   []harden.Step  // the Hardening Status
	rec     *harden.Record // nil without a Hardening Record
	lockWhy string         // the Lockout Guard's refusal to lock the Default Cloud Users
	hst     bool           // the Hardening Status shows, not the wizard
	table   table
	w, ht   int
	form    form // the wizard
}

func newHardening(m *harden.Machine) tea.Model {
	f := newForm("", "Admin user", "SSH port", "Private key", "Steps", "Rotate key")
	f.hints[fUser], f.hints[fPort] = "must not be root / ubuntu / system", "blank = keep current"
	f.opts[fKey] = options{names: []string{"show once on screen", "save to file"}, on: []bool{true, false}, radio: true, text: true}
	f.opts[fSteps] = options{names: []string{"Firewall", "fail2ban", "Auto updates", "sysctl"}, on: []bool{true, true, true, true}}
	f.opts[fRotate] = options{names: []string{"replace the Admin User's keys"}, on: []bool{false}}
	for i := range f.inputs {
		f.inputs[i].SetWidth(20)
	}
	return hardening{m: m, table: newTable("STEP", "STATE", "", ""), form: f}
}

func (h hardening) Init() tea.Cmd {
	return func() tea.Msg {
		rec, _ := harden.LoadRecord(h.m.Root) // unreadable = none: live checks still tell Done/Missing
		msg := hardeningMsg{steps: h.m.Status(rec), rec: rec}
		if s, ok := stepOf(msg.steps, "cloud-users"); ok && s.State != harden.Done {
			users, err := h.m.ManagedUsers()
			if err == nil {
				_, err = cloudUsersAdmin(users, rec)
			}
			if err != nil {
				msg.lockWhy = err.Error()
			}
		}
		return msg
	}
}

// stepOf is the step of steps with id; false if there is none.
func stepOf(steps []harden.Step, id string) (harden.Step, bool) {
	i := slices.IndexFunc(steps, func(s harden.Step) bool { return s.ID == id })
	if i < 0 {
		return harden.Step{}, false
	}
	return steps[i], true
}

func (h hardening) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case hardeningMsg:
		h.loaded, h.steps, h.rec, h.lockWhy = true, msg.steps, msg.rec, msg.lockWhy
		ssh, _ := stepOf(msg.steps, "ssh") // key-only SSH
		h.hst = ssh.State == harden.Done
		h.table.setRows(h.rows())
		return h, nil
	case taskDoneMsg:
		return h, h.Init()
	case tea.WindowSizeMsg:
		h.w, h.ht = msg.Width, msg.Height
		return h, nil
	}
	if h.hst {
		return h.statusUpdate(msg)
	}
	if click, ok := msg.(tea.MouseClickMsg); ok { // [ Start Hardening ]
		msg = mouse(h.layout(), click)
	}
	f, ev := h.form.update(msg)
	h.form = f
	switch ev {
	case cancelled:
		return h, Back
	case submitted:
		return h.start()
	}
	return h, nil
}

// start turns the form into `vpsctl harden` arguments and runs them as the
// Hardening Task.
func (h hardening) start() (tea.Model, tea.Cmd) {
	var args []string
	for _, a := range [][]string{{"--user", h.form.value(fUser)}, {"--port", h.form.value(fPort)}} {
		if v := strings.TrimSpace(a[1]); v != "" {
			args = append(args, a[0], v)
		}
	}
	if h.form.opts[fKey].on[1] {
		v := strings.TrimSpace(h.form.value(fKey))
		if v == "" {
			h.form.err = "save to file: type the key file's path"
			return h, nil
		}
		args = append(args, "--key-out", v)
	}
	if h.form.opts[fRotate].on[0] {
		args = append(args, "--rotate-key")
	}
	for i, on := range h.form.opts[fSteps].on {
		if !on {
			args = append(args, skipFlags[i])
		}
	}
	o, err := harden.ParseFlags(args)
	if err != nil {
		h.form.err = err.Error()
		return h, nil
	}
	port := o.Port // the port to log in on at the Verify Gate
	if port == 0 {
		port, _ = h.m.CurrentPort()
	}
	var steps []taskStep
	runSteps, summary := harden.Steps(o)
	for _, s := range runSteps {
		steps = append(steps, taskStep{s.Name, func(r system.Runner, out io.Writer) error {
			return s.Do(rawKeyMachine(taskMachine(h.m, r), taskTerminal(out)), out, taskGate(out, gateCommand(h.m.Root, port, o.User)))
		}})
	}
	return h, func() tea.Msg {
		return startTaskMsg{name: "Hardening", action: "harden " + strings.Join(args, " "), steps: steps, summarize: summary}
	}
}

// layout is the Hardening Status, or the wizard: header with the badge, the
// form and [ Start Hardening ].
func (h hardening) layout() *lipgloss.Compositor {
	if h.hst {
		return h.statusLayout()
	}
	title, badge := titleStyle.Render("Hardening"), errStyle.Render(glyph("✗")+" NOT HARDENED")
	head := title + strings.Repeat(" ", max(h.w-ansi.StringWidth(title)-ansi.StringWidth(badge), 1)) + badge
	return stack(head, h.form.view(), "", buttonRow(button{"enter", "Start Hardening", ""}))
}

func (h hardening) View() tea.View {
	if !h.loaded {
		return tea.NewView(titleStyle.Render("Hardening") + "\n\nloading…")
	}
	return tea.NewView(h.layout().Render())
}
