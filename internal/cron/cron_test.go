package cron_test

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/anhvandev/vpsctl/internal/cron"
	"github.com/anhvandev/vpsctl/internal/system"
)

// crontabTool fakes `crontab -u NAME -l` and `crontab -u NAME FILE` over a
// map of installed crontabs; FILE is read when installed.
type crontabTool map[string]string

func (c crontabTool) Run(name string, args ...string) (system.Result, error) {
	if name != "crontab" || len(args) != 3 || args[0] != "-u" {
		return (&system.Fake{}).Run(name, args...)
	}
	if args[2] == "-l" {
		tab, ok := c[args[1]]
		if !ok {
			return system.Result{Code: 1, Stderr: "no crontab for " + args[1] + "\n"}, nil
		}
		return system.Result{Stdout: tab}, nil
	}
	b, err := os.ReadFile(args[2])
	if err != nil {
		return system.Result{}, err
	}
	c[args[1]] = string(b)
	return system.Result{}, nil
}

func TestValidate(t *testing.T) {
	for _, ok := range []string{
		"* * * * * /bin/true",
		"0 3 * * * /usr/local/bin/backup --all",
		"*/15 0-23/2 1,15 jan-jun mon-fri echo hi",
		"59 23 31 12 7 x",
		"0 0 * DEC Sun x",
		"@reboot /bin/start",
		"@daily x", "@hourly x", "@weekly x", "@monthly x", "@yearly x", "@annually x", "@midnight x",
	} {
		if err := cron.Validate(ok); err != nil {
			t.Errorf("Validate(%q) = %v, want ok", ok, err)
		}
	}
	for _, bad := range []string{
		"", "* * * * *", "@daily", "@often x",
		"60 * * * * x", "* 24 * * * x", "* * 0 * * x", "* * * 13 * x", "* * * * 8 x",
		"*/0 * * * * x", "5-1 * * * * x", "a * * * * x", "* * * * x", "1,,2 * * * * x",
		"* * * * * x\n* * * * * y",
	} {
		if cron.Validate(bad) == nil {
			t.Errorf("Validate(%q) = nil, want an error", bad)
		}
	}
}

func TestEntriesSkipsCommentsAndEnvironment(t *testing.T) {
	tool := crontabTool{"root": "# backups\nMAILTO=ops@example.com\n\n0 3 * * * /usr/local/bin/backup\n@reboot /bin/start\n"}
	got, err := cron.Entries(tool, "root")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"0 3 * * * /usr/local/bin/backup", "@reboot /bin/start"}; !slices.Equal(got, want) {
		t.Errorf("Entries = %q, want %q", got, want)
	}
	if got, err := cron.Entries(tool, "alice"); err != nil || len(got) != 0 {
		t.Errorf("no crontab: Entries = %q, %v; want none", got, err)
	}
}

func TestReplaceKeepsOtherLines(t *testing.T) {
	tool := crontabTool{"alice": "# keep me\nPATH=/usr/bin:/bin\n0 3 * * * old\n"}
	if err := cron.Replace(tool, "alice", "0 3 * * * old", "0 4 * * * new"); err != nil {
		t.Fatal(err)
	}
	if err := cron.Replace(tool, "alice", "", "@daily added"); err != nil {
		t.Fatal(err)
	}
	if want := "# keep me\nPATH=/usr/bin:/bin\n0 4 * * * new\n@daily added\n"; tool["alice"] != want {
		t.Errorf("after edit+add:\n%q\nwant\n%q", tool["alice"], want)
	}
	if err := cron.Replace(tool, "alice", "0 4 * * * new", ""); err != nil {
		t.Fatal(err)
	}
	if want := "# keep me\nPATH=/usr/bin:/bin\n@daily added\n"; tool["alice"] != want {
		t.Errorf("after delete:\n%q\nwant\n%q", tool["alice"], want)
	}
	if err := cron.Replace(tool, "bob", "", "@hourly first"); err != nil || tool["bob"] != "@hourly first\n" {
		t.Errorf("add to empty crontab: %q, %v", tool["bob"], err)
	}
}

func TestReplaceRejectsBeforeWriting(t *testing.T) {
	tool := crontabTool{"alice": "0 3 * * * old\n"}
	if err := cron.Replace(tool, "alice", "0 3 * * * old", "61 * * * * new"); err == nil {
		t.Error("invalid schedule accepted")
	}
	// An entry changed by hand meanwhile is not silently overwritten.
	if err := cron.Replace(tool, "alice", "0 9 * * * gone", "@daily x"); err == nil || !strings.Contains(err.Error(), "no longer") {
		t.Errorf("stale entry: err = %v", err)
	}
	if tool["alice"] != "0 3 * * * old\n" {
		t.Errorf("crontab written: %q", tool["alice"])
	}
}

func TestReplaceReportsCrontabFailure(t *testing.T) {
	r := &system.Fake{Results: map[string]system.Result{"crontab -u alice -l": {Code: 1, Stderr: "must be privileged\n"}}}
	if err := cron.Replace(r, "alice", "", "@daily x"); err == nil || !strings.Contains(err.Error(), "must be privileged") {
		t.Errorf("err = %v", err)
	}
}
