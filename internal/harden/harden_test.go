package harden

import (
	"errors"
	"io"
	"slices"
	"testing"

	"github.com/anhvandev/vpsctl/internal/firewall"
)

// fakeHost records every step in order; fail[step] makes that step fail.
type fakeHost struct {
	calls     []string
	fail      map[string]bool
	plan      Plan
	waitSaved bool    // last InstallKey waitSaved
	record    *Record // the saved Hardening Record
}

func newHost() *fakeHost {
	return &fakeHost{fail: map[string]bool{}, plan: Plan{OldPort: 22, Port: 2222}}
}

func (h *fakeHost) step(name string) error {
	h.calls = append(h.calls, name)
	if h.fail[name] {
		return errors.New(name + " failed")
	}
	return nil
}

func (h *fakeHost) EnsureAdmin(string) error { return h.step("admin") }
func (h *fakeHost) InstallKey(_, _ string, _, waitSaved bool) error {
	h.waitSaved = waitSaved
	return h.step("key")
}
func (h *fakeHost) CurrentPort() (int, error)        { return h.plan.OldPort, h.step("port") }
func (h *fakeHost) PreLockAssertions(string) error   { return h.step("assert") }
func (h *fakeHost) LockDefaultCloudUsers() error     { return h.step("lock") }
func (h *fakeHost) BlockCloudInitReinjection() error { return h.step("cloudinit") }
func (h *fakeHost) Fail2ban(int) error               { return h.step("fail2ban") }
func (h *fakeHost) AutoUpdates() error               { return h.step("updates") }
func (h *fakeHost) Sysctl() error                    { return h.step("sysctl") }
func (h *fakeHost) SaveRecord(r Record) error        { h.record = &r; return nil }
func (h *fakeHost) EnsureFirewall(int) (firewall.Backend, error) {
	return nil, h.step("firewall")
}
func (h *fakeHost) BeginSSH(firewall.Backend, int, string) (Change, Plan, error) {
	return fakeChange{h}, h.plan, h.step("begin")
}

type fakeChange struct{ h *fakeHost }

func (c fakeChange) StageA() error  { return c.h.step("stageA") }
func (c fakeChange) StageB() error  { return c.h.step("stageB") }
func (c fakeChange) Restore() error { return c.h.step("restore") }

func yes(string) (bool, error) { return true, nil }

func TestFlowOrder(t *testing.T) {
	h := newHost()
	if err := Run(Options{User: "alice", Port: 2222}, h, io.Discard, yes); err != nil {
		t.Fatal(err)
	}
	want := []string{"admin", "key", "port", "firewall", "begin", "stageA", "assert", "stageB",
		"lock", "cloudinit", "fail2ban", "updates", "sysctl"}
	if !slices.Equal(h.calls, want) {
		t.Fatalf("calls\n got %v\nwant %v", h.calls, want)
	}
}

// The TTY key waits for `saved` unless --yes (automation has no operator).
func TestKeyWaitsForSavedUnlessYes(t *testing.T) {
	for _, yesFlag := range []bool{false, true} {
		h := newHost()
		if err := Run(Options{User: "alice", Yes: yesFlag}, h, io.Discard, yes); err != nil {
			t.Fatal(err)
		}
		if h.waitSaved == yesFlag {
			t.Fatalf("--yes=%v: waitSaved=%v", yesFlag, h.waitSaved)
		}
	}
}

func TestOwnFailuresBetweenStagesRestore(t *testing.T) {
	h := newHost()
	h.fail["assert"] = true
	err := Run(Options{User: "alice", Yes: true}, h, io.Discard, nil)
	if err == nil || !slices.Contains(h.calls, "restore") || slices.Contains(h.calls, "stageB") {
		t.Fatalf("err=%v calls=%v: want restore and no Stage B", err, h.calls)
	}
}

func TestOperatorStopAtGateRestoresAndStops(t *testing.T) {
	h := newHost()
	no := func(string) (bool, error) { return false, nil }
	err := Run(Options{User: "alice"}, h, io.Discard, no)
	if !errors.Is(err, ErrStopped) {
		t.Fatalf("err = %v, want ErrStopped", err)
	}
	if h.calls[len(h.calls)-1] != "restore" || slices.Contains(h.calls, "assert") {
		t.Fatalf("calls = %v: want restore last, no pre-lock assertions", h.calls)
	}
}

func TestNoTTYAtGateRestores(t *testing.T) {
	h := newHost()
	noTTY := func(string) (bool, error) { return false, errors.New("open /dev/tty: no such device") }
	err := Run(Options{User: "alice"}, h, io.Discard, noTTY)
	if err == nil || errors.Is(err, ErrStopped) || !slices.Contains(h.calls, "restore") {
		t.Fatalf("err=%v calls=%v", err, h.calls)
	}
}

func TestHardenedReRunSkipsStageAAndGate(t *testing.T) {
	h := newHost()
	h.plan = Plan{OldPort: 22, Port: 22, StageBLive: true}
	asked := false
	ask := func(string) (bool, error) { asked = true; return true, nil }
	if err := Run(Options{User: "alice"}, h, io.Discard, ask); err != nil {
		t.Fatal(err)
	}
	if asked || slices.Contains(h.calls, "stageA") || !slices.Contains(h.calls, "stageB") {
		t.Fatalf("asked=%v calls=%v", asked, h.calls)
	}
}

func TestSkipFlagsAndOptionalStepFailuresAreNotFatal(t *testing.T) {
	h := newHost()
	h.fail["fail2ban"], h.fail["sysctl"] = true, true
	o := Options{User: "alice", Yes: true, SkipFirewall: true, SkipUpdates: true}
	if err := Run(o, h, io.Discard, nil); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(h.calls, "firewall") || slices.Contains(h.calls, "updates") {
		t.Fatalf("skipped steps ran: %v", h.calls)
	}
}

// A run records who ran it, the Admin User, the steps the operator skipped
// and the ones it applied; an optional step that failed is not applied.
func TestRunSavesHardeningRecord(t *testing.T) {
	t.Setenv("SUDO_USER", "anh")
	h := newHost()
	h.fail["fail2ban"] = true
	o := Options{User: "alice", Yes: true, SkipFirewall: true, SkipUpdates: true}
	if err := Run(o, h, io.Discard, nil); err != nil {
		t.Fatal(err)
	}
	r := h.record
	if r == nil || r.Admin != "alice" || r.By != "anh" || r.Ran.IsZero() || !slices.Equal(r.Skipped, []string{"firewall", "updates"}) {
		t.Fatalf("record = %+v", r)
	}
	var applied []string
	for id := range r.Applied {
		applied = append(applied, id)
	}
	slices.Sort(applied)
	if want := []string{"admin", "cloud-init", "cloud-users", "port", "ssh", "sysctl"}; !slices.Equal(applied, want) {
		t.Errorf("applied %v, want %v", applied, want)
	}
}

// A run that stops at the Verify Gate still records what it applied before
// the gate (the Admin User); the SSH change was restored, so not ssh.
func TestStoppedRunSavesAppliedSoFar(t *testing.T) {
	h := newHost()
	Run(Options{User: "alice"}, h, io.Discard, func(string) (bool, error) { return false, nil })
	r := h.record
	if r == nil || r.Admin != "alice" || r.Applied["admin"].IsZero() || !r.Applied["ssh"].IsZero() {
		t.Errorf("record = %+v", r)
	}
}

// Steps are the run's Hardening Steps, without the skipped ones.
func TestStepsLeaveOutSkipped(t *testing.T) {
	var names []string
	for _, s := range Steps(Options{User: "alice", SkipFirewall: true, SkipSysctl: true}) {
		names = append(names, s.Name)
	}
	want := []string{"Admin User + key", "Key-only SSH, no root login (Verify Gate)", "Default Cloud Users locked",
		"cloud-init re-injection block", "fail2ban", "Automatic security updates"}
	if !slices.Equal(names, want) {
		t.Errorf("steps\n got %q\nwant %q", names, want)
	}
}

func TestParseFlags(t *testing.T) {
	o, err := ParseFlags([]string{"--user", "alice", "--port", "2222", "--yes", "--key-out", "/k", "--rotate-key"})
	want := Options{User: "alice", Port: 2222, Yes: true, KeyOut: "/k", RotateKey: true}
	if err != nil || o != want {
		t.Fatalf("got %+v, %v", o, err)
	}
	for _, args := range [][]string{
		{"--port", "2222"},
		{"--user", "alice", "--port", "2222", "--skip-firewall"},
		{"--user", "alice", "--port", "70000"},
	} {
		if _, err := ParseFlags(args); err == nil {
			t.Errorf("%v: accepted, want an error", args)
		}
	}
}
