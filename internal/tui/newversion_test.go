package tui

import (
	"strings"
	"testing"
)

// A newer release shows a notice; the TUI never updates on its own.
func TestNewVersionNotice(t *testing.T) {
	tm := start(debianHost(t))
	waitFor(t, tm, "Uptime")
	tm.Send(NewVersionMsg("v2.1.0"))
	waitFor(t, tm, "v2.1.0 available")
	wantAll(t, quitView(t, tm), "v2.1.0 available", "sudo vpsctl self-update")
}

func TestNoNoticeWithoutNewVersion(t *testing.T) {
	tm := start(debianHost(t))
	waitFor(t, tm, "Uptime")
	if v := quitView(t, tm); strings.Contains(v, "available") {
		t.Errorf("notice shown without a newer release:\n%s", v)
	}
}
