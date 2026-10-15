package tui

import (
	"io"
	"slices"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

const dockerPs = `docker ps -a --format {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}\t{{.Ports}}\t{{.Label "com.docker.compose.project"}}`

// dockerHost is debianHost with Docker: shop-web-1 publishes 8080 on all
// interfaces (IPv4 and IPv6), shop-db-1 publishes 5432 on loopback only,
// old-api is a plain exited container.
func dockerHost(t *testing.T) *testHost {
	h := debianHost(t)
	h.fake.Results["docker version --format {{.Server.Version}}"] = system.Result{Stdout: "28.1.1\n"}
	h.fake.Results[dockerPs] = system.Result{Stdout: "" +
		"77aa\told-api\tapi:0.3\texited\tExited (0) 2 days ago\t\t\n" +
		"a1\tshop-web-1\tnginx:1.27\trunning\tUp 3 hours\t0.0.0.0:8080->80/tcp, [::]:8080->80/tcp\tshop\n" +
		"b2\tshop-db-1\tpostgres:16\trunning\tUp 3 hours\t127.0.0.1:5432->5432/tcp\tshop\n"}
	return h
}

// The Firewall screen shows the all-interfaces Published Port as a row that
// bypasses the firewall, with the fix in its detail box; its Remove is
// disabled. The loopback-only 5432 gets no row.
func TestFirewallShowsPublishedPort(t *testing.T) {
	h := dockerHost(t)
	tm := openFirewall(t, h)
	tm.Type("jjj") // 22, 80, 5432 rules, then the Published Port
	waitFor(t, tm, "Published by container")
	tm.Type("d")
	v := ctrlCView(t, tm)
	wantAll(t, v, "8080  tcp    (Docker)", "⚠ Published Port, bypasses firewall", "Published by container shop-web-1 (compose: shop)", "regardless of ufw",
		"127.0.0.1:8080:80", "[ Open in Docker ]")
	if strings.Count(v, "(Docker)") != 1 {
		t.Errorf("want exactly one Published Port row (IPv4+IPv6 are one, loopback none):\n%s", v)
	}
	if strings.Contains(v, "Remove rule") {
		t.Errorf("Remove asked for a Published Port:\n%s", v)
	}
	if got := mutations(h); len(got) != 0 {
		t.Errorf("ran %q", got)
	}
	for _, c := range h.fake.Calls { // read-only towards Docker and its firewall rules
		if strings.HasPrefix(c, "iptables") || strings.HasPrefix(c, "nft") ||
			strings.HasPrefix(c, "docker") && c != dockerPs && c != "docker version --format {{.Server.Version}}" {
			t.Errorf("ran %q", c)
		}
	}
}

// Opening a Published Port in Docker lands on its container.
func TestFirewallOpenInDocker(t *testing.T) {
	tm := openFirewall(t, dockerHost(t))
	tm.Type("jjj")
	waitFor(t, tm, "[ Open in Docker ]")
	tm.Type("o")
	waitFor(t, tm, "CONTAINER")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape})
	waitFor(t, tm, "q quit")
	v := quitView(t, tm)
	wantAll(t, v, "▌shop-web-1")
}

// dockerView is the loaded Docker screen on h, sized as in a 120×40 terminal.
func dockerView(h *testHost) string {
	s := screens["Docker"](harden.NewMachine(h.fake, h.host, h.root, io.Discard))
	s, _ = s.Update(tea.WindowSizeMsg{Width: 92, Height: 36})
	s, _ = s.Update(s.Init()())
	return ansi.Strip(s.View().Content)
}

// Containers are grouped by compose project, plain ones last; only the port
// on all interfaces is flagged, its IPv4 and IPv6 bindings shown once.
func TestDockerListsContainersByProject(t *testing.T) {
	v := dockerView(dockerHost(t))
	wantAll(t, v, "3 containers · ⚠ 1 Published Port")
	var order []string
	for _, line := range strings.Split(v, "\n") {
		f := strings.Fields(strings.NewReplacer("│", " ", "▌", " ").Replace(line))
		if len(f) > 0 && slices.Contains([]string{"shop-db-1", "shop-web-1", "old-api"}, f[0]) {
			order = append(order, strings.Join(f, " "))
		}
	}
	want := []string{
		"shop-db-1 shop ● running 127.0.0.1:5432→5432 postgres:16",
		"shop-web-1 shop ● running ⚠ 0.0.0.0:8080→80 nginx:1.27",
		"old-api - · exited(0) - api:0.3",
	}
	if !slices.Equal(order, want) {
		t.Errorf("rows = %q, want %q\n%s", order, want, v)
	}
}

// Without Docker the menu has no Docker item and the Overview says so; with
// it, both show.
func TestDockerMenuItemOnlyWithDocker(t *testing.T) {
	tm := start(debianHost(t))
	waitFor(t, tm, "RAM")
	v := quitView(t, tm)
	wantAll(t, v, "Docker     not installed")
	if strings.Contains(v, "│   Docker ") {
		t.Errorf("Docker in the menu without Docker:\n%s", v)
	}

	tm = start(dockerHost(t))
	waitFor(t, tm, "RAM")
	v = quitView(t, tm)
	wantAll(t, v, "│   Docker ", "Docker     3 containers · ⚠ 1 Published Port bypassing the firewall")
}
