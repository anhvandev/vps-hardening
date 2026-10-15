package docker

import (
	"errors"
	"slices"
	"testing"

	"github.com/anhvandev/vpsctl/internal/system"
)

// fake is a host whose `docker ps` prints stdout.
func fake(stdout string) *system.Fake {
	return &system.Fake{Results: map[string]system.Result{
		"docker version --format {{.Server.Version}}": {Stdout: "28.1.1\n"},
		"docker ps -a --format " + format:             {Stdout: stdout},
	}}
}

func TestContainersWithAndWithoutComposeLabels(t *testing.T) {
	f := fake("944a49360ca2\tvps\tvpsctl-e2e:ubuntu-24.04\trunning\tUp 8 hours\t0.0.0.0:2222->2222/tcp, [::]:2222->2222/tcp, 127.0.0.1:2200->22/tcp\t\n" +
		"1e3545a942b4\taxe-gateway-backend-1\taxe-gateway-backend\trunning\tUp 21 hours (healthy)\t5150/tcp\taxe-gateway\n" +
		"77aa\told-api\tapi:0.3\texited\tExited (0) 2 days ago\t\t\n")
	cs, err := Containers(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 3 {
		t.Fatalf("got %d containers: %+v", len(cs), cs)
	}
	vps := cs[0]
	if vps.ID != "944a49360ca2" || vps.Name != "vps" || vps.Project != "" || vps.Image != "vpsctl-e2e:ubuntu-24.04" || vps.State != "running" {
		t.Errorf("plain container = %+v", vps)
	}
	want := []Port{
		{HostIP: "0.0.0.0", HostPort: "2222", Port: "2222", Proto: "tcp"},
		{HostIP: "[::]", HostPort: "2222", Port: "2222", Proto: "tcp"},
		{HostIP: "127.0.0.1", HostPort: "2200", Port: "22", Proto: "tcp"},
	}
	if !slices.Equal(vps.Ports, want) {
		t.Errorf("ports = %+v, want %+v", vps.Ports, want)
	}
	if got := cs[1]; got.Project != "axe-gateway" || got.Status != "Up 21 hours (healthy)" {
		t.Errorf("compose container = %+v", got)
	}
	if got := cs[1].Published(); len(got) != 0 {
		t.Errorf("exposed-only port counted as published: %+v", got)
	}
	if got := cs[2]; got.State != "exited" || got.Status != "Exited (0) 2 days ago" || len(got.Ports) != 0 {
		t.Errorf("exited container = %+v", got)
	}
}

func TestPublishedOnAllInterfaces(t *testing.T) {
	cs, err := Containers(fake("a\tweb\tnginx\trunning\tUp\t" +
		"0.0.0.0:8080->80/tcp, :::8443->443/tcp, [::1]:9000->9000/tcp, ::1:9001->9001/tcp, 127.0.0.1:5432->5432/tcp, " +
		"0.0.0.0:8000-8001->8000-8001/udp, 53/udp\tshop\n"))
	if err != nil {
		t.Fatal(err)
	}
	var open []string
	for _, p := range cs[0].Published() {
		if p.AllInterfaces() {
			open = append(open, p.String())
		}
	}
	want := []string{"0.0.0.0:8080->80/tcp", ":::8443->443/tcp", "0.0.0.0:8000-8001->8000-8001/udp"}
	if !slices.Equal(open, want) {
		t.Errorf("all-interface Published Ports = %q, want %q", open, want)
	}
	if n := len(cs[0].Published()); n != 6 {
		t.Errorf("%d Published Ports, want 6 (53/udp is only exposed)", n)
	}
}

func TestNotInstalled(t *testing.T) {
	if _, err := Containers(&system.Fake{}); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("missing binary: %v", err)
	}
	f := fake("")
	f.Results["docker version --format {{.Server.Version}}"] = system.Result{Code: 1, Stderr: "Cannot connect to the Docker daemon"}
	f.Results["docker ps -a --format "+format] = system.Result{Code: 1, Stderr: "Cannot connect to the Docker daemon\n"}
	if _, err := Containers(f); err == nil || errors.Is(err, ErrNotInstalled) {
		t.Errorf("daemon down: %v, want a non-ErrNotInstalled error", err)
	}
	if !Installed(f) || Installed(&system.Fake{}) {
		t.Error("Installed: want true with the binary (even with the daemon down), false without")
	}
}
