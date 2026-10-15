package service_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/anhvandev/vpsctl/internal/service"
	"github.com/anhvandev/vpsctl/internal/system"
)

// Loaded Timers come with their next run and target Service; installed but
// unloaded ones have neither. Templates are left out.
func TestListTimers(t *testing.T) {
	r := &system.Fake{Results: map[string]system.Result{
		"systemctl list-timers --all --plain --no-legend --no-pager": {Stdout: "" +
			"Thu 2026-10-15 09:09:00 UTC 6min Thu 2026-10-15 08:39:03 UTC 23min ago phpsessionclean.timer phpsessionclean.service\n" +
			"-                           -    Wed 2026-10-14 06:00:00 UTC 1 day ago   backup.timer          backup.service\n" +
			"n/a n/a n/a n/a apt-daily.timer apt-daily.service\n"},
		"systemctl list-unit-files --type=timer --plain --no-legend --no-pager": {Stdout: "" +
			"apt-daily.timer enabled enabled\nbackup.timer enabled enabled\nfstrim.timer disabled enabled\n" +
			"phpsessionclean.timer enabled enabled\nsnapper@.timer static -\n"},
	}}
	got, err := service.ListTimers(r)
	if err != nil {
		t.Fatal(err)
	}
	want := []service.Timer{
		{Name: "apt-daily.timer", Service: "apt-daily.service"},
		{Name: "backup.timer", Service: "backup.service"},
		{Name: "fstrim.timer"},
		{Name: "phpsessionclean.timer", Next: "Thu 2026-10-15 09:09:00 UTC", Service: "phpsessionclean.service"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListTimers =\n%+v\nwant\n%+v", got, want)
	}
}

func timerRunner() *system.Fake {
	return &system.Fake{Results: map[string]system.Result{
		"systemd-analyze calendar *-*-* 03:00":               {Stdout: "  Original form: *-*-* 03:00\nNormalized form: *-*-* 03:00:00\n"},
		"systemd-analyze calendar bogus":                     {Code: 1, Stderr: "Failed to parse calendar specification 'bogus': Invalid argument\n"},
		"systemctl show -p LoadState --value backup.service": {Stdout: "loaded\n"},
		"systemctl show -p LoadState --value nope.service":   {Stdout: "not-found\n"},
	}}
}

func TestTimerSpecRendersTimerUnit(t *testing.T) {
	unit, content, err := service.TimerSpec{Name: "backup", Schedule: "*-*-* 03:00", Service: "backup"}.Unit(timerRunner())
	if err != nil {
		t.Fatal(err)
	}
	want := "[Unit]\nDescription=Run backup.service on *-*-* 03:00\n\n[Timer]\nOnCalendar=*-*-* 03:00\nUnit=backup.service\n\n" +
		"[Install]\nWantedBy=timers.target\n"
	if unit != "backup.timer" || string(content) != want {
		t.Errorf("Unit = %q,\n%s", unit, content)
	}
}

// The schedule is checked with `systemd-analyze calendar` and the target must
// be a Service systemd knows.
func TestTimerSpecRejectsInvalidFields(t *testing.T) {
	ok := service.TimerSpec{Name: "backup.timer", Schedule: "*-*-* 03:00", Service: "backup.service"}
	for want, change := range map[string]func(*service.TimerSpec){
		"invalid name":                func(s *service.TimerSpec) { s.Name = "../x" },
		"Failed to parse calendar":    func(s *service.TimerSpec) { s.Schedule = "bogus" },
		"schedule is required":        func(s *service.TimerSpec) { s.Schedule = " " },
		"invalid Service":             func(s *service.TimerSpec) { s.Service = "a b" },
		"nope.service does not exist": func(s *service.TimerSpec) { s.Service = "nope" },
		"line breaks":                 func(s *service.TimerSpec) { s.Schedule = "daily\nExecStart=/bin/evil" },
	} {
		s := ok
		change(&s)
		if _, _, err := s.Unit(timerRunner()); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v", want, err)
		}
	}
	if _, _, err := ok.Unit(timerRunner()); err != nil {
		t.Errorf("valid spec: %v", err)
	}
}
