package service

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/anhvandev/vpsctl/internal/system"
)

// Spec is the form behind a new Service: everything but Name, Command, User
// and Restart may be left empty and is then left out of the unit.
type Spec struct {
	Name        string // "myapp" or "myapp.service"
	Description string
	Command     string // ExecStart
	User        string
	WorkingDir  string
	Restart     string // a systemd Restart= policy
	Environment string // "KEY=VALUE KEY2=VALUE2", systemd quoting
}

// RestartPolicies are the values systemd accepts for Restart=.
var RestartPolicies = []string{"no", "on-success", "on-failure", "on-abnormal", "on-watchdog", "on-abort", "always"}

// validName is a unit name vpsctl creates: no templates (@), no paths.
var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,200}$`)

// UnitPath is where vpsctl writes a unit it creates, under root.
func UnitPath(root, unit string) string {
	return filepath.Join(root, "/etc/systemd/system", unit)
}

// CheckNew refuses unit unless its name is valid and nothing by that name
// exists: neither a file at UnitPath nor a unit systemd knows (from any unit
// directory, masked included).
func CheckNew(r system.Runner, root, unit string) error {
	if !validName.MatchString(unit) {
		return fmt.Errorf("invalid unit name %q", unit)
	}
	if _, err := os.Stat(UnitPath(root, unit)); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s already exists", unit)
	}
	state, err := systemctl(r, "show", "-p", "LoadState", "--value", unit)
	if err != nil {
		return err
	}
	if strings.TrimSpace(state) != "not-found" {
		return fmt.Errorf("%s already exists", unit)
	}
	return nil
}

// Create writes content as the new unit (see CheckNew) at UnitPath, then
// verifies and reloads as Apply does: a unit that fails verify is removed.
func Create(r system.Runner, root, unit string, content []byte) error {
	if err := CheckNew(r, root, unit); err != nil {
		return err
	}
	return Apply(r, UnitPath(root, unit), unit, content)
}

// Unit validates s and renders it as the unit file of a Service started at
// boot once enabled.
func (s Spec) Unit() (unit string, content []byte, err error) {
	name := strings.TrimSuffix(s.Name, ".service")
	switch {
	case !validName.MatchString(name):
		return "", nil, fmt.Errorf("invalid name %q: letters, digits and _ . : - only", s.Name)
	case strings.TrimSpace(s.Command) == "":
		return "", nil, errors.New("command is required")
	case s.User == "":
		return "", nil, errors.New("user is required (root only if picked explicitly)")
	case !slices.Contains(RestartPolicies, s.Restart):
		return "", nil, fmt.Errorf("invalid restart policy %q: want one of %s", s.Restart, strings.Join(RestartPolicies, ", "))
	case strings.ContainsAny(s.Description+s.Command+s.User+s.WorkingDir+s.Environment, "\r\n"):
		return "", nil, errors.New("fields cannot contain line breaks")
	}
	var b strings.Builder
	line := func(key, value string) {
		if value != "" {
			b.WriteString(key + "=" + value + "\n")
		}
	}
	b.WriteString("[Unit]\n")
	line("Description", s.Description)
	b.WriteString("\n[Service]\n")
	line("ExecStart", s.Command)
	line("User", s.User)
	line("WorkingDirectory", s.WorkingDir)
	line("Restart", s.Restart)
	line("Environment", s.Environment)
	b.WriteString("\n[Install]\nWantedBy=multi-user.target\n")
	return name + ".service", []byte(b.String()), nil
}
