package service

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/anhvandev/vpsctl/internal/system"
)

// Timer is one systemd .timer unit as systemd sees it now.
type Timer struct {
	Name    string // "backup.timer"
	Next    string // next run, "Thu 2026-10-15 09:09:00 UTC"; "" if none scheduled
	Service string // the unit it activates; "" if the Timer is not loaded
}

// ListTimers reads every Timer, loaded or only installed, sorted by name.
// Templates (foo@.timer) are left out.
func ListTimers(r system.Runner) ([]Timer, error) {
	loaded, err := systemctl(r, "list-timers", "--all", "--plain", "--no-legend", "--no-pager")
	if err != nil {
		return nil, err
	}
	files, err := systemctl(r, "list-unit-files", "--type=timer", "--plain", "--no-legend", "--no-pager")
	if err != nil {
		return nil, err
	}
	var list []Timer
	// "NEXT LEFT LAST PASSED UNIT ACTIVATES": NEXT is 4 words, or "-"/"n/a" if none.
	for _, line := range strings.Split(loaded, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		t := Timer{Name: f[len(f)-2], Service: f[len(f)-1]}
		if len(f) >= 6 && f[0] != "-" && f[0] != "n/a" {
			t.Next = strings.Join(f[:4], " ")
		}
		list = append(list, t)
	}
	// "UNIT STATE [PRESET]"
	for _, line := range strings.Split(files, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasSuffix(f[0], "@.timer") {
			continue
		}
		if !slices.ContainsFunc(list, func(t Timer) bool { return t.Name == f[0] }) {
			list = append(list, Timer{Name: f[0]})
		}
	}
	slices.SortFunc(list, func(a, b Timer) int { return strings.Compare(a.Name, b.Name) })
	return list, nil
}

// TimerSpec is the form behind a new Timer: when (an OnCalendar= schedule)
// and which Service it starts.
type TimerSpec struct {
	Name     string // "backup" or "backup.timer"
	Schedule string // systemd calendar syntax: "daily", "*-*-* 03:00", ...
	Service  string // "backup" or "backup.service"
}

// Unit validates s, the schedule with `systemd-analyze calendar` and the
// Service as one systemd knows, and renders it as the unit file of a Timer
// started at boot once enabled.
func (s TimerSpec) Unit(r system.Runner) (unit string, content []byte, err error) {
	name := strings.TrimSuffix(s.Name, ".timer")
	svc := strings.TrimSuffix(s.Service, ".service")
	switch {
	case !validName.MatchString(name):
		return "", nil, fmt.Errorf("invalid name %q: letters, digits and _ . : - only", s.Name)
	case !validName.MatchString(svc):
		return "", nil, fmt.Errorf("invalid Service %q", s.Service)
	case strings.TrimSpace(s.Schedule) == "":
		return "", nil, errors.New("schedule is required")
	case strings.ContainsAny(s.Schedule, "\r\n"):
		return "", nil, errors.New("fields cannot contain line breaks")
	}
	svc += ".service"
	if _, err := run(r, "systemd-analyze", "calendar", s.Schedule); err != nil {
		return "", nil, err
	}
	state, err := systemctl(r, "show", "-p", "LoadState", "--value", svc)
	if err != nil {
		return "", nil, err
	}
	if strings.TrimSpace(state) == "not-found" {
		return "", nil, fmt.Errorf("%s does not exist", svc)
	}
	return name + ".timer", []byte("[Unit]\nDescription=Run " + svc + " on " + s.Schedule + "\n\n" +
		"[Timer]\nOnCalendar=" + s.Schedule + "\nUnit=" + svc + "\n\n" +
		"[Install]\nWantedBy=timers.target\n"), nil
}
