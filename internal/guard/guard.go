// Package guard is the Lockout Guard: a pure decision, over a snapshot of
// system facts, on whether a proposed action would cut the operator's own SSH
// path. It runs no commands. A refusal is final; there is no override.
//
// Adding a rule = a func(Facts, any) error appended to rules, plus the facts
// and action types it needs. Each rule ignores actions it does not judge.
package guard

import (
	"errors"
	"fmt"
	"slices"

	"github.com/anhvandev/vpsctl/internal/firewall"
)

// Facts is the snapshot of the system the guard decides on. The caller reads
// it under the global lock, right before the action.
type Facts struct {
	SSHPort int             // port sshd listens on now; 0 = unknown
	Rules   []firewall.Rule // current Firewall Rules
	// Listening is every tcp Listening Port now; nil = unknown.
	Listening []int
}

// RemoveRule proposes deleting one Firewall Rule.
type RemoveRule struct{ Rule firewall.Rule }

// ChangeSSHPort proposes moving sshd to Port.
type ChangeSSHPort struct{ Port int }

var rules = []func(Facts, any) error{keepSSHPortOpen, freeSSHPort}

// Check allows action (nil) or refuses it with the reason, starting "refused: ".
func Check(f Facts, action any) error {
	for _, rule := range rules {
		if err := rule(f, action); err != nil {
			return err
		}
	}
	return nil
}

// keepSSHPortOpen refuses removing a rule that allows the SSH port unless the
// port stays open to anywhere without it. A source-limited rule does not count:
// the operator may not be connecting from that source.
func keepSSHPortOpen(f Facts, action any) error {
	a, ok := action.(RemoveRule)
	if !ok {
		return nil
	}
	if f.SSHPort == 0 {
		return errors.New("refused: SSH port unknown, cannot tell whether this rule keeps you connected")
	}
	if !allowsSSH(a.Rule, f.SSHPort) {
		return nil
	}
	if slices.ContainsFunc(f.Rules, func(r firewall.Rule) bool {
		return r != a.Rule && r.From == "" && allowsSSH(r, f.SSHPort)
	}) {
		return nil
	}
	return fmt.Errorf("refused: SSH port %d would no longer be open to anywhere", f.SSHPort)
}

// allowsSSH: r lets tcp traffic reach port.
func allowsSSH(r firewall.Rule, port int) bool {
	return (r.Proto == "" || r.Proto == "tcp") && port >= r.Port && port <= max(r.End, r.Port)
}

// freeSSHPort refuses moving SSH to a port another process already listens
// on: sshd could not bind it.
func freeSSHPort(f Facts, action any) error {
	a, ok := action.(ChangeSSHPort)
	if !ok || a.Port == f.SSHPort || !slices.Contains(f.Listening, a.Port) {
		return nil
	}
	return fmt.Errorf("refused: port %d is already a Listening Port", a.Port)
}
