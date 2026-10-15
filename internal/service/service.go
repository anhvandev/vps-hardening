// Package service lists Services and runs lifecycle actions on them through
// systemctl. Actions on Protected Units are refused here (internal/guard), so
// every caller gets the Lockout Guard.
package service

import (
	"fmt"
	"slices"
	"strings"

	"github.com/anhvandev/vpsctl/internal/guard"
	"github.com/anhvandev/vpsctl/internal/system"
)

// Service is one systemd .service unit as systemd sees it now.
type Service struct {
	Name        string // "nginx.service"
	Active      string // ActiveState: active, inactive, failed, activating, ...
	Sub         string // SubState: running, exited, dead, failed, ...
	Enabled     string // UnitFileState: enabled, disabled, static, masked, ... ("" if no unit file)
	Description string
}

// List reads every Service, loaded or only installed, sorted by name.
// Units referenced but not found and templates (foo@.service) are left out.
func List(r system.Runner) ([]Service, error) {
	units, err := systemctl(r, "list-units", "--type=service", "--all", "--plain", "--no-legend", "--no-pager")
	if err != nil {
		return nil, err
	}
	files, err := systemctl(r, "list-unit-files", "--type=service", "--plain", "--no-legend", "--no-pager")
	if err != nil {
		return nil, err
	}
	var list []Service
	// "UNIT LOAD ACTIVE SUB DESCRIPTION..."
	for _, line := range strings.Split(units, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[1] == "not-found" {
			continue
		}
		list = append(list, Service{Name: f[0], Active: f[2], Sub: f[3], Description: strings.Join(f[4:], " ")})
	}
	index := map[string]int{}
	for i, s := range list {
		index[s.Name] = i
	}
	// "UNIT STATE [PRESET]"
	for _, line := range strings.Split(files, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasSuffix(f[0], "@.service") {
			continue
		}
		if i, ok := index[f[0]]; ok {
			list[i].Enabled = f[1]
		} else {
			list = append(list, Service{Name: f[0], Active: "inactive", Sub: "dead", Enabled: f[1]})
		}
	}
	slices.SortFunc(list, func(a, b Service) int { return strings.Compare(a.Name, b.Name) })
	return list, nil
}

// Do runs `systemctl verb unit` (start, stop, restart, enable, disable)
// unless the Lockout Guard refuses it as a Protected Unit action.
func Do(r system.Runner, verb, unit string) error {
	if err := guard.Check(guard.Facts{}, guard.UnitAction{Unit: unit, Verb: verb}); err != nil {
		return err
	}
	_, err := systemctl(r, verb, unit)
	return err
}

// systemctl runs systemctl args, returning stdout or an error carrying stderr.
func systemctl(r system.Runner, args ...string) (string, error) {
	res, err := r.Run("systemctl", args...)
	if err == nil && res.Code != 0 {
		err = fmt.Errorf("systemctl %s: exit %d: %s", strings.Join(args, " "), res.Code, strings.TrimSpace(res.Stderr))
	}
	return res.Stdout, err
}
