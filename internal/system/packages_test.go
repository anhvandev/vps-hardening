package system

import (
	"slices"
	"testing"
)

func TestAptUpdateRunsOnceBeforeFirstInstall(t *testing.T) {
	f := &Fake{Results: map[string]Result{
		"env DEBIAN_FRONTEND=noninteractive apt-get update -qq":              {},
		"env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw":      {},
		"env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban": {},
	}}
	p := &Packages{R: f, Manager: "apt"}
	if err := p.Install("ufw"); err != nil {
		t.Fatal(err)
	}
	if err := p.Install("fail2ban"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"env DEBIAN_FRONTEND=noninteractive apt-get update -qq",
		"env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw",
		"env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban",
	}
	if !slices.Equal(f.Calls, want) {
		t.Fatalf("calls:\n%q\nwant:\n%q", f.Calls, want)
	}
}

func TestDnfInstallAndFailureIsError(t *testing.T) {
	f := &Fake{Results: map[string]Result{
		"dnf install -y firewalld": {},
		"dnf install -y nope":      {Code: 1, Stderr: "No match for argument: nope"},
	}}
	p := &Packages{R: f, Manager: "dnf"}
	if err := p.Install("firewalld"); err != nil {
		t.Fatal(err)
	}
	if err := p.Install("nope"); err == nil {
		t.Fatal("expected error on non-zero exit")
	}
	if err := (&Packages{R: f}).Install("x"); err == nil {
		t.Fatal("expected error for unknown package manager")
	}
}
