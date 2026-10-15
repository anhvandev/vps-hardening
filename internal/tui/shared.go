package tui

// Helpers shared by several screens: the logged mutation path and the
// operator's SSH session.

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/anhvandev/vpsctl/internal/actionlog"
	"github.com/anhvandev/vpsctl/internal/harden"
)

// logMutation takes the global lock under root, runs do and appends one
// action-log line. A busy lock returns its holder and runs nothing.
func logMutation(root, action string, do func() error) error {
	lk, err := actionlog.Lock(filepath.Join(root, actionlog.LockPath))
	if err != nil {
		return err
	}
	defer lk.Close()
	err = do()
	appendLog(root, action, err)
	return err
}

// appendLog appends action's action-log line under root: ok, stopped (at the
// Verify Gate, as the CLI logs it), or failed with err.
func appendLog(root, action string, err error) {
	result := "ok"
	switch {
	case errors.Is(err, harden.ErrStopped):
		result = "stopped"
	case err != nil:
		result = "failed: " + err.Error()
	}
	actionlog.Append(filepath.Join(root, actionlog.LogPath), action, result) // failures to log are ignored
}

// sessionIP is the client IP of the operator's SSH session, "" when not
// found, e.g. on the provider console.
func sessionIP(root string) string {
	if f := sshConnection(root); len(f) > 0 {
		return f[0]
	}
	return ""
}

// sshConnection is the operator's SSH_CONNECTION (client IP, client port,
// server IP, server port) from the nearest ancestor that has it (sudo drops
// it from our own env). nil when not found.
func sshConnection(root string) []string {
	pid := strconv.Itoa(os.Getpid())
	for range 32 { // bounded walk up the process tree
		env, _ := os.ReadFile(filepath.Join(root, "/proc", pid, "environ"))
		for _, kv := range strings.Split(string(env), "\x00") {
			if v, ok := strings.CutPrefix(kv, "SSH_CONNECTION="); ok {
				if f := strings.Fields(v); len(f) > 0 {
					return f
				}
			}
		}
		stat, err := os.ReadFile(filepath.Join(root, "/proc", pid, "stat"))
		i := strings.LastIndexByte(string(stat), ')')
		if err != nil || i < 0 {
			return nil
		}
		f := strings.Fields(string(stat[i+1:])) // state, ppid, ...
		if len(f) < 2 || f[1] == "0" || f[1] == "1" {
			return nil
		}
		pid = f[1]
	}
	return nil
}
