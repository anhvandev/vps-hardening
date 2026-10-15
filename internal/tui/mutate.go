package tui

import (
	"os"
	"path/filepath"

	"github.com/anhvandev/vpsctl/internal/actionlog"
	"github.com/anhvandev/vpsctl/internal/harden"
)

// mutate is how every screen changes the host: take the global lock, run do,
// append one action-log line ("<action>: ok" or "<action>: failed: <err>"),
// and return do's error for the screen to show inline. A busy lock refuses
// the action ("locked by <name> (pid N)") without running do or logging.
// do reads the facts it decides on (e.g. for the Lockout Guard) itself, so
// they are read under the lock.
func mutate(m *harden.Machine, action string, do func() error) error {
	lockPath := filepath.Join(m.Root, actionlog.LockPath)
	os.MkdirAll(filepath.Dir(lockPath), 0o755) // /run exists on a real host, maybe not under a test root
	lk, err := actionlog.Lock(lockPath)
	if err != nil {
		return err
	}
	defer lk.Close()
	err = do()
	result := "ok"
	if err != nil {
		result = "failed: " + err.Error()
	}
	actionlog.Append(filepath.Join(m.Root, actionlog.LogPath), action, result) // failures to log are ignored, as in the CLI
	return err
}
