package fail2ban

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/anhvandev/vpsctl/internal/system"
)

func TestJailsAndBans(t *testing.T) {
	f := &system.Fake{Results: map[string]system.Result{
		"fail2ban-client status": {Stdout: "Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, recidive\n"},
		"fail2ban-client status sshd": {Stdout: "Status for the jail: sshd\n`- Actions\n" +
			"   |- Currently banned:\t2\n   `- Banned IP list:\t198.51.100.7 2001:db8::9\n"},
		"fail2ban-client status recidive": {Stdout: "`- Actions\n   `- Banned IP list:\t\n"},
	}}
	jails, err := Jails(f)
	if err != nil || !slices.Equal(jails, []string{"sshd", "recidive"}) {
		t.Fatalf("Jails = %q, %v", jails, err)
	}
	want := []Ban{{"sshd", "198.51.100.7"}, {"sshd", "2001:db8::9"}}
	if got := Bans(f, jails); !slices.Equal(got, want) {
		t.Errorf("Bans = %v, want %v", got, want)
	}
}

func TestJailsDown(t *testing.T) {
	if _, err := Jails(&system.Fake{}); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("missing binary: %v", err)
	}
	f := &system.Fake{Results: map[string]system.Result{"fail2ban-client status": {Code: 255}}}
	if _, err := Jails(f); !errors.Is(err, ErrNotRunning) {
		t.Errorf("stopped: %v", err)
	}
}

func TestUnbanFailsOnNonZeroExit(t *testing.T) {
	f := &system.Fake{Results: map[string]system.Result{"fail2ban-client set sshd unbanip 192.0.2.1": {Code: 1, Stderr: "no"}}}
	if err := Unban(f, Ban{"sshd", "192.0.2.1"}); err == nil {
		t.Error("non-zero exit: no error")
	}
}

func TestAddIgnoreKeepsEntriesAndReloads(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, DropIn)
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, []byte("[DEFAULT]\nignoreip = 10.0.0.0/8\n\n[sshd]\nenabled = true\n"), 0o644)
	f := &system.Fake{Results: map[string]system.Result{"fail2ban-client reload": {}}}

	if err := AddIgnore(f, root, "300.1.1.1"); err == nil || len(f.Calls) != 0 {
		t.Fatalf("invalid entry: err %v, calls %q", err, f.Calls)
	}
	for _, e := range []string{"203.0.113.5", "10.0.0.0/8"} {
		if err := AddIgnore(f, root, e); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(p)
	if want := "[DEFAULT]\nignoreip = 10.0.0.0/8 203.0.113.5\n\n[sshd]\nenabled = true\n"; string(b) != want {
		t.Errorf("drop-in =\n%s\nwant\n%s", b, want)
	}
	if got := Ignore(root); !slices.Equal(got, []string{"10.0.0.0/8", "203.0.113.5"}) {
		t.Errorf("Ignore = %q", got)
	}
	if !slices.Contains(f.Calls, "fail2ban-client reload") {
		t.Errorf("no reload in %q", f.Calls)
	}
}

func TestAddIgnoreWithoutIgnoreLineAddsDefault(t *testing.T) {
	root := t.TempDir()
	f := &system.Fake{Results: map[string]system.Result{"fail2ban-client reload": {}}}
	if err := AddIgnore(f, root, "192.0.2.0/24"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(root, DropIn))
	if want := "[DEFAULT]\nignoreip = 192.0.2.0/24\n\n"; string(b) != want {
		t.Errorf("drop-in = %q, want %q", b, want)
	}
}
