package user

import (
	"slices"
	"testing"

	"github.com/anhvandev/vpsctl/internal/system"
)

func TestManagedUsersAreHumanLoginsOnly(t *testing.T) {
	m := &Manager{R: &system.Fake{Results: map[string]system.Result{
		"getent passwd": {Stdout: "root:x:0:0:root:/root:/bin/bash\n" +
			"sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n" +
			"alice:x:1000:1000:Alice:/home/alice:/bin/bash\n" +
			"svc:x:1001:1001::/srv/svc:/usr/sbin/nologin\n" +
			"bob:x:1002:1002::/home/bob:/bin/zsh\n" +
			"ci:x:1003:1003::/home/ci:/bin/false\n" +
			"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"},
	}}}
	got, err := m.ManagedUsers()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"alice", "bob"}; !slices.Equal(got, want) {
		t.Errorf("ManagedUsers = %v, want %v", got, want)
	}
}
