// Package docker reads the live Docker containers and their Published Ports
// through a system.Runner. It never changes Docker's firewall rules.
package docker

import (
	"errors"
	"strings"

	"github.com/anhvandev/vpsctl/internal/system"
)

var ErrNotInstalled = errors.New("not installed")

// format lists containers without {{json .}}, which would make docker
// compute container sizes (slow).
const format = `{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}\t{{.Ports}}\t{{.Label "com.docker.compose.project"}}`

// Container is one container; Project is its compose project, "" for a plain one.
type Container struct {
	ID, Name, Image, State, Status, Project string
	Ports                                   []Port
}

// Port is one entry of docker's PORTS column. HostPort is "" for a port the
// container only exposes; Port and HostPort may be ranges ("8000-8001").
type Port struct{ HostIP, HostPort, Port, Proto string }

// Installed reports whether the docker binary is there (the daemon may be down).
func Installed(r system.Runner) bool {
	_, err := r.Run("docker", "version", "--format", "{{.Server.Version}}")
	return err == nil
}

// Containers lists every container, running or not; ErrNotInstalled without docker.
func Containers(r system.Runner) ([]Container, error) {
	res, err := r.Run("docker", "ps", "-a", "--format", format)
	switch {
	case err != nil:
		return nil, ErrNotInstalled
	case res.Code != 0:
		return nil, errors.New(strings.TrimSpace(res.Stderr))
	}
	var cs []Container
	for _, line := range strings.Split(res.Stdout, "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 7 {
			continue
		}
		c := Container{ID: f[0], Name: f[1], Image: f[2], State: f[3], Status: f[4], Project: f[6]}
		for _, p := range strings.Split(f[5], ", ") {
			if p != "" {
				c.Ports = append(c.Ports, parsePort(p))
			}
		}
		cs = append(cs, c)
	}
	return cs, nil
}

// parsePort reads "[hostIP:]hostPort->port/proto" or "port/proto". The host
// IP is "0.0.0.0", "[::]" (Docker 28) or "::" (older Docker, ":::8080->80/tcp").
func parsePort(s string) Port {
	var p Port
	host, ctr, published := strings.Cut(s, "->")
	if !published {
		ctr = host
	} else if i := strings.LastIndex(host, ":"); i >= 0 {
		p.HostIP, p.HostPort = host[:i], host[i+1:]
	} else {
		p.HostPort = host
	}
	p.Port, p.Proto, _ = strings.Cut(ctr, "/")
	return p
}

// Published is c's Published Ports: those docker maps to a host port.
func (c Container) Published() []Port {
	var ps []Port
	for _, p := range c.Ports {
		if p.HostPort != "" {
			ps = append(ps, p)
		}
	}
	return ps
}

// AllInterfaces reports a Published Port bound to every interface, so
// reachable from outside whatever the firewall says.
func (p Port) AllInterfaces() bool {
	switch p.HostIP {
	case "", "0.0.0.0", "::", "[::]":
		return p.HostPort != ""
	}
	return false
}

// String is the port as docker prints it.
func (p Port) String() string {
	s := p.Port + "/" + p.Proto
	switch {
	case p.HostPort == "":
		return s
	case p.HostIP == "":
		return p.HostPort + "->" + s
	}
	return p.HostIP + ":" + p.HostPort + "->" + s
}
