// Package cron reads and writes Cron Entries in root's and Managed Users'
// crontabs. Every read and write goes through the system crontab tool, so
// file permissions and cron daemon notification stay the tool's job.
package cron

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/anhvandev/vpsctl/internal/system"
)

// Entries lists user's Cron Entries in crontab order; comments, blank and
// environment lines are skipped. A user without a crontab has none.
func Entries(r system.Runner, user string) ([]string, error) {
	lines, err := read(r, user)
	return slices.DeleteFunc(lines, func(l string) bool { return !isEntry(l) }), err
}

// Replace swaps the Cron Entry old for new in user's crontab: old "" adds new,
// new "" deletes old. The crontab is re-read first so every other line
// (comments, environment, entries added by hand meanwhile) survives; an old
// entry no longer there is an error rather than a silent overwrite. An
// invalid new entry is rejected before anything is written.
func Replace(r system.Runner, user, old, new string) error {
	if new != "" {
		if err := Validate(new); err != nil {
			return err
		}
	}
	lines, err := read(r, user)
	if err != nil {
		return err
	}
	i := slices.Index(lines, old)
	switch {
	case old == "":
		lines = append(lines, new)
	case i < 0:
		return fmt.Errorf("%q is no longer in %s's crontab; reopen Cron", old, user)
	case new == "":
		lines = slices.Delete(lines, i, i+1)
	default:
		lines[i] = new
	}
	return write(r, user, lines)
}

// Validate checks one Cron Entry: a schedule of five fields or an @ shortcut,
// then a command, all on one line.
func Validate(entry string) error {
	if strings.ContainsAny(entry, "\r\n") {
		return errors.New("an entry is one line")
	}
	f := strings.Fields(entry)
	if len(f) > 0 && strings.HasPrefix(f[0], "@") {
		if !slices.Contains(shortcuts, f[0]) {
			return fmt.Errorf("unknown schedule %s", f[0])
		}
		if len(f) < 2 {
			return errors.New("no command")
		}
		return nil
	}
	if len(f) < 6 {
		return errors.New("want five schedule fields then a command, or an @ shortcut")
	}
	for i, fl := range fields {
		if err := fl.check(f[i]); err != nil {
			return fmt.Errorf("%s %q: %w", fl.name, f[i], err)
		}
	}
	return nil
}

var shortcuts = []string{"@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly"}

type field struct {
	name     string
	min, max int
	names    []string // names[i] stands for min+i
}

var fields = []field{
	{name: "minute", max: 59},
	{name: "hour", max: 23},
	{name: "day of month", min: 1, max: 31},
	{name: "month", min: 1, max: 12, names: []string{"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"}},
	{name: "day of week", max: 7, names: []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}},
}

// check accepts a comma list of *, N or N-M, each optionally /STEP.
func (fl field) check(s string) error {
	for _, item := range strings.Split(s, ",") {
		span, step, hasStep := strings.Cut(item, "/")
		if hasStep {
			if n, err := strconv.Atoi(step); err != nil || n < 1 {
				return fmt.Errorf("bad step %q", step)
			}
		}
		if span == "*" {
			continue
		}
		lo, hi, isRange := strings.Cut(span, "-")
		if hasStep && !isRange {
			return errors.New("a step needs * or a range")
		}
		a, err := fl.value(lo)
		if err != nil {
			return err
		}
		if isRange {
			b, err := fl.value(hi)
			if err != nil {
				return err
			}
			if a > b {
				return fmt.Errorf("range %s is backwards", span)
			}
		}
	}
	return nil
}

func (fl field) value(s string) (int, error) {
	if i := slices.Index(fl.names, strings.ToLower(s)); i >= 0 {
		return fl.min + i, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < fl.min || n > fl.max {
		return 0, fmt.Errorf("want %d-%d", fl.min, fl.max)
	}
	return n, nil
}

// isEntry: a job line starts with its minute field or an @ shortcut;
// comments start with # and environment lines with a name.
func isEntry(line string) bool {
	t := strings.TrimSpace(line)
	return t != "" && strings.ContainsRune("@*0123456789", rune(t[0]))
}

func read(r system.Runner, user string) ([]string, error) {
	res, err := r.Run("crontab", "-u", user, "-l")
	if err != nil {
		return nil, fmt.Errorf("crontab -u %s -l: %w", user, err)
	}
	if res.Code != 0 {
		if strings.Contains(res.Stderr, "no crontab for") {
			return nil, nil
		}
		return nil, fmt.Errorf("crontab -u %s -l: exit %d: %s", user, res.Code, strings.TrimSpace(res.Stderr))
	}
	if res.Stdout == "" {
		return nil, nil
	}
	return strings.Split(strings.TrimSuffix(res.Stdout, "\n"), "\n"), nil
}

// write installs lines as user's crontab with `crontab -u USER FILE`.
func write(r system.Runner, user string, lines []string) error {
	f, err := os.CreateTemp("", "vpsctl-crontab-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	data := ""
	if len(lines) > 0 {
		data = strings.Join(lines, "\n") + "\n"
	}
	_, err = f.WriteString(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	res, err := r.Run("crontab", "-u", user, f.Name())
	if err != nil {
		return fmt.Errorf("crontab -u %s: %w", user, err)
	}
	if res.Code != 0 {
		return fmt.Errorf("crontab -u %s: exit %d: %s", user, res.Code, strings.TrimSpace(res.Stderr))
	}
	return nil
}
