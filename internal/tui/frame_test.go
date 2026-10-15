package tui

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/anhvandev/vpsctl/internal/harden"
)

// startSized opens the TUI on h in a w×h virtual UTF-8 terminal.
func startSized(h *testHost, w, ht int) *teatest.TestModel {
	h.t.Setenv("TERM", "xterm-256color")
	if os.Getenv("LC_ALL") == "" {
		h.t.Setenv("LC_ALL", "C.UTF-8")
	}
	m := New(harden.NewMachine(h.fake, h.host, h.root, io.Discard), time.Now())
	return teatest.NewTestModel(h.t, m, teatest.WithInitialTermSize(w, ht))
}

// sizedHost is debianHost with a hostname and two CPUs.
func sizedHost(t *testing.T) *testHost {
	h := debianHost(t)
	h.write("/proc/sys/kernel/hostname", "prod-sg-01\n")
	h.write("/proc/cpuinfo", "processor\t: 0\nmodel name\t: x\n\nprocessor\t: 1\nmodel name\t: x\n")
	return h
}

func TestWideFrame(t *testing.T) {
	tm := startSized(sizedHost(t), 120, 40)
	waitFor(t, tm, "5432/tcp")
	v := quitView(t, tm)
	wantAll(t, v, "prod-sg-01", "Ubuntu 24.04", "2 vCPU · 4 GB", "⚠ Hardening 5/9",
		"SECURITY", "ACCESS", "WORKLOADS", "SYSTEM", "Hardening", "Task History", "? help", "q quit")
	for _, hidden := range []string{"Docker", "coming soon"} {
		if strings.Contains(leftCols(v, 26), hidden) {
			t.Errorf("unbuilt %q shown:\n%s", hidden, v)
		}
	}
	// The sidebar sits left of the open screen on the same rows.
	if !lineHas(v, "SECURITY", "Overview") {
		t.Errorf("sidebar not beside the content:\n%s", v)
	}
}

func TestBadgeOnUnhardenedHost(t *testing.T) {
	h := sizedHost(t)
	h.unharden()
	tm := startSized(h, 120, 40)
	waitFor(t, tm, "5432/tcp")
	v := quitView(t, tm)
	wantAll(t, v, "✗ NOT HARDENED")
	if strings.Contains(v, "Hardening 5/9") {
		t.Errorf("x/y badge on unhardened host:\n%s", v)
	}
}

// lineHas reports whether one line of v contains all of subs.
func lineHas(v string, subs ...string) bool {
	for _, line := range strings.Split(v, "\n") {
		ok := true
		for _, s := range subs {
			ok = ok && strings.Contains(line, s)
		}
		if ok {
			return true
		}
	}
	return false
}

// leftCols is the first n columns of every line of v: the sidebar.
func leftCols(v string, n int) string {
	var b strings.Builder
	for _, line := range strings.Split(v, "\n") {
		r := []rune(line)
		b.WriteString(string(r[:min(n, len(r))]) + "\n")
	}
	return b.String()
}

// finalView presses q and returns the last frame as plain text, from the
// sidebar (where q quits).
func finalView(t *testing.T, tm *teatest.TestModel) string {
	t.Helper()
	tm.Type("q")
	return ansi.Strip(tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second)).View().Content)
}

// Below 100 columns the sidebar is a tab bar with the current group; tab
// opens the whole sidebar over the content.
func TestNarrowFrame(t *testing.T) {
	tm := startSized(sizedHost(t), 90, 30)
	waitFor(t, tm, "5432/tcp")
	tm.Type("j") // Overview → Updates, still SYSTEM
	v := finalView(t, tm)
	wantAll(t, v, "SYSTEM  Overview · Updates · Disk · Swap · Task History", "tab menu", "5432/tcp")
	if strings.Contains(v, "WORKLOADS") {
		t.Errorf("full sidebar shown on a narrow terminal:\n%s", v)
	}

	tm = startSized(sizedHost(t), 90, 30)
	waitFor(t, tm, "5432/tcp")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyTab})
	waitFor(t, tm, "WORKLOADS")
	tm.Type("kkk") // Overview → Cron → Timers → Services
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "esc back")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape})
	waitFor(t, tm, "enter open")
	v = finalView(t, tm)
	wantAll(t, v, "WORKLOADS  Services · Timers · Cron")
	if strings.Contains(v, "SECURITY") {
		t.Errorf("sidebar overlay still open after opening a screen:\n%s", v)
	}
}

func click(x, y int) tea.MouseClickMsg {
	return tea.MouseClickMsg{X: x, Y: y, Button: tea.MouseLeft}
}

func TestClickSidebarOpensScreen(t *testing.T) {
	h := sizedHost(t)
	h.fake.Results["ss -Hltunp"] = ssOut
	tm := startSized(h, 120, 40)
	waitFor(t, tm, "5432/tcp")
	tm.Send(click(5, 3)) // row 3: SECURITY, Hardening, Firewall
	waitFor(t, tm, "esc back")
	tm.Send(click(5, 9))  // the WORKLOADS heading: nothing happens
	tm.Send(click(5, 12)) // row 12: … WORKLOADS, Services, Timers, Cron
	tm.Send(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	v := ansi.Strip(tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second)).View().Content)
	if !lineHas(v, "SECURITY", "│ Cron") || !strings.Contains(v, "▌ Cron") {
		t.Errorf("clicking Cron did not open it:\n%s", v)
	}
}

func TestClickBadgeOpensHardening(t *testing.T) {
	h := sizedHost(t)
	h.unharden()
	tm := startSized(h, 120, 40)
	waitFor(t, tm, "NOT HARDENED")
	tm.Send(click(110, 0))
	waitFor(t, tm, "Admin user")
}

// Mouse capture is on by default; m turns it off so the terminal selects text.
func TestMToggleMouse(t *testing.T) {
	tm := startSized(sizedHost(t), 120, 40)
	waitFor(t, tm, "5432/tcp")
	tm.Type("m")
	tm.Type("q")
	if got := tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second)).View().MouseMode; got != tea.MouseModeNone {
		t.Errorf("mouse mode after m = %v, want none", got)
	}

	tm = startSized(sizedHost(t), 120, 40)
	waitFor(t, tm, "5432/tcp")
	tm.Type("mm")
	tm.Type("q")
	if got := tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second)).View().MouseMode; got != tea.MouseModeCellMotion {
		t.Errorf("mouse mode after m m = %v, want cell motion", got)
	}
}

func TestHelpOverlay(t *testing.T) {
	tm := startSized(sizedHost(t), 120, 40)
	waitFor(t, tm, "5432/tcp")
	tm.Type("?")
	waitFor(t, tm, "Shift+drag to select text")
	tm.Type("x") // any key closes it
	v := finalView(t, tm)
	if strings.Contains(v, "Shift+drag") {
		t.Errorf("help still shown:\n%s", v)
	}
	wantAll(t, v, "5432/tcp")
}

func TestASCIIFallback(t *testing.T) {
	t.Setenv("LC_ALL", "C")
	h := sizedHost(t)
	h.unharden()
	tm := startSized(h, 120, 40)
	waitFor(t, tm, "5432/tcp")
	v := finalView(t, tm)
	wantAll(t, v, "x NOT HARDENED", "+ vpsctl - prod-sg-01 - Ubuntu 24.04", "> Overview")
	if strings.ContainsAny(v, "●✓✗⚠▶◆▌─│┌") {
		t.Errorf("non-ASCII symbols on a non-UTF-8 terminal:\n%s", v)
	}
}

func TestTooSmallTerminal(t *testing.T) {
	for _, size := range [][2]int{{79, 40}, {120, 23}} {
		tm := startSized(sizedHost(t), size[0], size[1])
		waitFor(t, tm, "terminal too small (need 80×24)")
		if v := finalView(t, tm); v != "terminal too small (need 80×24)" {
			t.Errorf("%dx%d shows more than the message:\n%s", size[0], size[1], v)
		}
	}
}
