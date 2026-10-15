package guard

import (
	"testing"

	"github.com/anhvandev/vpsctl/internal/user"
)

// alice and bob are both usable Admin Users (sudo + key + unlocked).
var (
	alice = user.ManagedUser{Name: "alice", Sudo: true, Keys: 1}
	bob   = user.ManagedUser{Name: "bob", Sudo: true, Keys: 2}
	carol = user.ManagedUser{Name: "carol", Keys: 1} // no sudo
)

func TestUserActions(t *testing.T) {
	both := []user.ManagedUser{alice, bob, carol}
	onlyAlice := []user.ManagedUser{alice, {Name: "bob", Sudo: true, Locked: true, Keys: 1}, carol}
	for _, tc := range []struct {
		name    string
		session string // "" = root on the provider console, no session user
		users   []user.ManagedUser
		target  string
		verb    string
		refuse  bool
	}{
		{"alice locks bob", "alice", both, "bob", "lock", false},
		{"alice locks alice", "alice", both, "alice", "lock", true},
		{"alice deletes alice", "alice", both, "alice", "delete", true},
		{"alice revokes her own sudo", "alice", both, "alice", "revoke-sudo", true},
		{"alice removes one of her two keys", "alice", []user.ManagedUser{{Name: "alice", Sudo: true, Keys: 2}}, "alice", "remove-key", false},
		{"alice removes her last key while bob is usable", "alice", both, "alice", "remove-key", false},
		{"alice removes the last key of the last usable Admin User, herself", "alice", onlyAlice, "alice", "remove-key", true},
		{"bob revokes vpsctl sudo of the last usable Admin User, who keeps admin-group sudo", "bob",
			[]user.ManagedUser{{Name: "alice", Sudo: true, AdminGroup: true, Keys: 1}}, "alice", "revoke-sudo", false},
		{"alice grants herself sudo", "alice", both, "alice", "grant-sudo", false},
		{"alice deletes bob", "alice", both, "bob", "delete", false},
		{"bob revokes sudo of the last usable Admin User", "bob", onlyAlice, "alice", "revoke-sudo", true},
		{"bob locks the last usable Admin User", "bob", onlyAlice, "alice", "lock", true},
		{"bob deletes the last usable Admin User", "bob", onlyAlice, "alice", "delete", true},
		{"bob removes the last key of the last usable Admin User", "bob", onlyAlice, "alice", "remove-key", true},
		{"carol removes one of two keys of the last usable Admin User", "carol", []user.ManagedUser{bob}, "bob", "remove-key", false},
		{"lock a non-admin with one usable Admin User", "alice", onlyAlice, "carol", "lock", false},
		{"unlock while no Admin User is usable", "", []user.ManagedUser{{Name: "bob", Sudo: true, Locked: true, Keys: 1}}, "bob", "unlock", false},
		{"console: lock bob", "", both, "bob", "lock", false},
		{"console: lock alice while bob is usable", "", both, "alice", "lock", false},
		{"console: revoke sudo of the last usable Admin User", "", onlyAlice, "alice", "revoke-sudo", true},
		{"console: delete the last usable Admin User", "", onlyAlice, "alice", "delete", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Check(Facts{SessionUser: tc.session, Users: tc.users}, UserAction{User: tc.target, Verb: tc.verb})
			if refused := err != nil; refused != tc.refuse {
				t.Errorf("refused = %v (%v), want %v", refused, err, tc.refuse)
			}
		})
	}
}

func TestUserRefusalsGiveReason(t *testing.T) {
	err := Check(Facts{SessionUser: "alice", Users: []user.ManagedUser{alice, bob}}, UserAction{User: "alice", Verb: "lock"})
	if err == nil || err.Error() != "refused: alice is your own session's user, cannot lock it" {
		t.Errorf("own user: err = %v", err)
	}
	err = Check(Facts{Users: []user.ManagedUser{alice}}, UserAction{User: "alice", Verb: "delete"})
	if err == nil || err.Error() != "refused: alice is the last usable Admin User (sudo + key + unlocked)" {
		t.Errorf("last admin: err = %v", err)
	}
}
