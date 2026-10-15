package tui

// Helpers shared by several screens: the logged mutation path, the
// operator's SSH session, the firewall and the Listening Ports.

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/anhvandev/vpsctl/internal/actionlog"
	"github.com/anhvandev/vpsctl/internal/firewall"
	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
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

// quiet marks an error whose text may carry secrets (e.g. a Cron Entry's
// command): the action log gets a bare "failed", the screen the full text.
type quiet struct{ error }

// appendLog appends action's action-log line under root: ok, stopped (at the
// Verify Gate, as the CLI logs it), or failed with err (bare if quiet).
func appendLog(root, action string, err error) {
	result := "ok"
	switch {
	case errors.Is(err, harden.ErrStopped):
		result = "stopped"
	case errors.As(err, new(quiet)):
		result = "failed"
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

// firewallRules reads the firewall state ("active", "inactive", "not
// installed", "not managed on this distro") and its Firewall Rules; err is
// set whenever the rules could not be listed. ufw lists its rules while
// inactive; a stopped firewalld cannot.
func firewallRules(m *harden.Machine) (state string, rules []firewall.Rule, err error) {
	var res system.Result
	var active bool
	switch m.Host.Family {
	case "debian":
		res, err = m.R.Run("ufw", "status")
		active = res.Code == 0 && strings.Contains(res.Stdout, "Status: active")
	case "rhel":
		res, err = m.R.Run("firewall-cmd", "--state")
		active = res.Code == 0
	default:
		return "not managed on this distro", nil, firewall.ErrNoBackend
	}
	if err != nil {
		return "not installed", nil, err
	}
	state = "inactive"
	if active {
		state = "active"
	}
	fw, _ := firewall.New(m.Host, m.R, m.Pkgs)
	rules, err = fw.List()
	return state, rules, err
}

// listeningPort is a Listening Port: a tcp socket in LISTEN or a bound udp socket.
type listeningPort struct {
	proto string
	port  int
}

// listeningPorts reads `ss -Hltun` (no header, listening tcp+udp, numeric):
// "Netid State Recv-Q Send-Q Local:Port Peer:Port". nil if ss failed.
func listeningPorts(r system.Runner) []listeningPort {
	res, err := r.Run("ss", "-Hltun")
	if err != nil || res.Code != 0 {
		return nil
	}
	ls := []listeningPort{}
	for _, line := range strings.Split(res.Stdout, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		local := f[4]
		if port, err := strconv.Atoi(local[strings.LastIndex(local, ":")+1:]); err == nil {
			ls = append(ls, listeningPort{f[0], port})
		}
	}
	return ls
}
