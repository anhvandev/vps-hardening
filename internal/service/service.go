// Package service lists Services and runs lifecycle actions on them through
// systemctl, and reads or follows their journal. Actions on Protected Units are refused here (internal/guard), so
// every caller gets the Lockout Guard.
package service

import (
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

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

// Status is what systemd knows of a Service's current run.
type Status struct {
	Since  time.Time // when it entered its state; zero if unknown
	Result string    // how it last ended: success, exit-code, signal, timeout, ...
	Exit   string    // ExecMainStatus: the exit code (or signal number)
	Mem    uint64    // bytes; 0 if unknown
	PID    int       // main PID; 0 if none
}

// Show reads the Status of units in one `systemctl show`, in units' order.
func Show(r system.Runner, units []string) ([]Status, error) {
	out, err := systemctl(r, append([]string{"show", "-p", "Id,StateChangeTimestamp,Result,ExecMainStatus,MemoryCurrent,MainPID"}, units...)...)
	if err != nil {
		return nil, err
	}
	var list []Status
	for _, line := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(line, "=")
		if k == "Id" { // each unit's properties start with its Id
			list = append(list, Status{})
		}
		if len(list) == 0 {
			continue
		}
		s := &list[len(list)-1]
		switch k {
		case "StateChangeTimestamp":
			s.Since, _ = time.ParseInLocation("Mon 2006-01-02 15:04:05 MST", v, time.Local)
		case "Result":
			s.Result = v
		case "ExecMainStatus":
			s.Exit = v
		case "MemoryCurrent":
			if n, err := strconv.ParseUint(v, 10, 64); err == nil && n != math.MaxUint64 { // max: not accounted
				s.Mem = n
			}
		case "MainPID":
			s.PID, _ = strconv.Atoi(v)
		}
	}
	if len(list) != len(units) {
		return nil, fmt.Errorf("systemctl show: %d units read, want %d", len(list), len(units))
	}
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

// EnableStart enables, then starts unit (a newly created Service or Timer).
func EnableStart(r system.Runner, unit string) error {
	if err := Do(r, "enable", unit); err != nil {
		return err
	}
	return Do(r, "start", unit)
}

// Journal reads the last n journal lines of unit, never the whole history.
func Journal(r system.Runner, unit string, n int) ([]string, error) {
	out, err := run(r, "journalctl", "-u", unit, "-n", strconv.Itoa(n), "--no-pager")
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimRight(out, "\n"), "\n"), nil
}

// Follow streams unit's journal live, starting from its last n lines, until
// the returned stream is closed (which stops journalctl).
func Follow(r system.Runner, unit string, n int) (io.ReadCloser, error) {
	s, ok := r.(system.Streamer)
	if !ok {
		return nil, errors.New("live follow not supported by this runner")
	}
	return s.Stream("journalctl", "-u", unit, "-n", strconv.Itoa(n), "-f", "--no-pager")
}

func systemctl(r system.Runner, args ...string) (string, error) { return run(r, "systemctl", args...) }

// run runs name args, returning stdout or an error carrying stderr.
func run(r system.Runner, name string, args ...string) (string, error) {
	res, err := r.Run(name, args...)
	if err == nil && res.Code != 0 {
		err = fmt.Errorf("%s %s: exit %d: %s", name, strings.Join(args, " "), res.Code, strings.TrimSpace(res.Stderr))
	}
	return res.Stdout, err
}
