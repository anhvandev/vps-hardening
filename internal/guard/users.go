package guard

import (
	"fmt"
	"slices"

	"github.com/anhvandev/vpsctl/internal/user"
)

// UserAction proposes Verb ("grant-sudo", "revoke-sudo", "lock", "unlock",
// "remove-key" of one key, "delete") on the Managed User named User.
type UserAction struct{ User, Verb string }

func init() { rules = append(rules, keepOwnUser, keepUsableAdmin) }

// cuts are the verbs that can take a user's way in away.
var cuts = []string{"revoke-sudo", "lock", "remove-key", "delete"}

// keepOwnUser refuses cutting the session's own user: the operator would lose
// the account they are logged in as.
func keepOwnUser(f Facts, action any) error {
	a, ok := action.(UserAction)
	if !ok || f.SessionUser == "" || a.User != f.SessionUser || !slices.Contains(cuts, a.Verb) {
		return nil
	}
	return fmt.Errorf("refused: %s is your own session's user, cannot %s it", a.User, a.Verb)
}

// keepUsableAdmin refuses turning the last usable Admin User (sudo + key +
// unlocked) unusable. Revoking counts as losing sudo even when admin-group
// membership would keep it: the guard errs on the side of keeping a way in.
func keepUsableAdmin(f Facts, action any) error {
	a, ok := action.(UserAction)
	if !ok || !slices.Contains(cuts, a.Verb) {
		return nil
	}
	i := slices.IndexFunc(f.Users, func(u user.ManagedUser) bool { return u.Name == a.User })
	if i < 0 || !usable(f.Users[i]) {
		return nil
	}
	after := f.Users[i]
	switch a.Verb {
	case "revoke-sudo":
		after.Sudo = false
	case "lock":
		after.Locked = true
	case "remove-key":
		after.Keys--
	case "delete":
		after.Keys = 0
	}
	if usable(after) || slices.ContainsFunc(f.Users, func(u user.ManagedUser) bool { return u.Name != a.User && usable(u) }) {
		return nil
	}
	return fmt.Errorf("refused: %s is the last usable Admin User (sudo + key + unlocked)", a.User)
}

func usable(u user.ManagedUser) bool { return u.Sudo && u.Keys > 0 && !u.Locked }
