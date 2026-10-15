package harden

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/anhvandev/vpsctl/internal/fail2ban"
	"github.com/anhvandev/vpsctl/internal/user"
)

// State is a Hardening Step's state in the Hardening Status.
type State string

const (
	Done    State = "Done"
	Missing State = "Missing"
	Skipped State = "Skipped" // Missing, and the Record says the operator chose to skip it
)

// Step is one Hardening Step as Status reads it.
type Step struct {
	ID, Name string
	State    State
	Detail   string    // what the live check found ("anh · 1 key", "2222", "ufw") or why it failed
	Applied  time.Time // Missing and the Record says it was applied then; zero otherwise
}

// Status reads every Hardening Step live from the machine, in Hardening
// order. rec (nil when there is no Record) only tells Skipped and Applied
// apart for steps that are not Done.
func (m *Machine) Status(rec *Record) []Step {
	users, uerr := m.ManagedUsers()
	sshErr := m.SSH.KeyOnly()
	port, perr := m.CurrentPort()
	checks := []struct {
		id, name string
		check    func() (bool, string)
	}{
		{"admin", "Admin User + key", func() (bool, string) { return m.adminDone(users, uerr, rec) }},
		{"ssh", "Key-only SSH, no root login", func() (bool, string) { return sshErr == nil, errText(sshErr) }},
		{"port", "SSH port", func() (bool, string) {
			if perr != nil {
				return false, perr.Error()
			}
			return true, strconv.Itoa(port)
		}},
		{"firewall", "Firewall on", m.firewallOn},
		{"cloud-users", "Default Cloud Users locked", func() (bool, string) { return cloudUsersLocked(users, uerr) }},
		{"cloud-init", "cloud-init re-injection block", m.cloudInitBlocked},
		{"fail2ban", "fail2ban", m.fail2banOn},
		{"updates", "Automatic security updates", m.autoUpdatesOn},
		{"sysctl", "sysctl hardening", m.sysctlLive},
	}
	var steps []Step
	for _, c := range checks {
		done, detail := c.check()
		st := Step{ID: c.id, Name: c.name, State: Done, Detail: detail}
		switch {
		case done:
		case rec != nil && slices.Contains(rec.Skipped, c.id):
			st.State = Skipped
		default:
			st.State = Missing
			if rec != nil {
				st.Applied = rec.Applied[c.id]
			}
		}
		steps = append(steps, st)
	}
	return steps
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// adminDone: a Managed User the operator can log in as and escalate with,
// the Record's Admin User first.
func (m *Machine) adminDone(users []user.ManagedUser, err error, rec *Record) (bool, string) {
	if err != nil {
		return false, err.Error()
	}
	u, ok := AdminUser(users, rec)
	if !ok {
		return false, "no user with a key and passwordless sudo"
	}
	return true, fmt.Sprintf("%s · %d key%s", u.Name, u.Keys, map[bool]string{true: "s"}[u.Keys != 1])
}

// AdminUser is the Admin User among users: one the operator can log in as
// and escalate with (Usable) that is not a Default Cloud User, the Record's
// Admin User first. false when there is none.
func AdminUser(users []user.ManagedUser, rec *Record) (user.ManagedUser, bool) {
	var usable []user.ManagedUser
	for _, u := range users {
		if u.Usable() && !slices.Contains(user.DefaultCloudUsers, u.Name) {
			usable = append(usable, u)
		}
	}
	if len(usable) == 0 {
		return user.ManagedUser{}, false
	}
	if rec != nil {
		if i := slices.IndexFunc(usable, func(u user.ManagedUser) bool { return u.Name == rec.Admin }); i >= 0 {
			return usable[i], true
		}
	}
	return usable[0], true
}

// cloudUsersLocked: every Default Cloud User present is locked with no key.
func cloudUsersLocked(users []user.ManagedUser, err error) (bool, string) {
	if err != nil {
		return false, err.Error()
	}
	var names, open []string
	for _, u := range users {
		if slices.Contains(user.DefaultCloudUsers, u.Name) {
			names = append(names, u.Name)
			if !u.Locked || u.Keys > 0 {
				open = append(open, u.Name)
			}
		}
	}
	if len(open) > 0 {
		return false, strings.Join(open, ", ") + " not locked"
	}
	return true, cmp.Or(strings.Join(names, ", "), "none present")
}

func (m *Machine) firewallOn() (bool, string) {
	switch m.Host.Family {
	case "debian":
		res, err := m.R.Run("ufw", "status")
		if err == nil && res.Code == 0 && strings.Contains(res.Stdout, "Status: active") {
			return true, "ufw"
		}
		return false, "ufw not active"
	case "rhel":
		if m.ok("firewall-cmd", "--state") {
			return true, "firewalld"
		}
		return false, "firewalld not running"
	}
	return false, "not managed on this distro"
}

// cloudInitBlocked: vpsctl's cloud-init drop-in, or no cloud-init at all.
func (m *Machine) cloudInitBlocked() (bool, string) {
	dir := filepath.Join(m.Root, "/etc/cloud/cloud.cfg.d")
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return true, "no cloud-init"
	}
	if _, err := os.Stat(filepath.Join(dir, "99-vpsctl.cfg")); err != nil {
		return false, ""
	}
	return true, ""
}

func (m *Machine) fail2banOn() (bool, string) {
	jails, err := fail2ban.Jails(m.R)
	switch {
	case err != nil:
		return false, err.Error()
	case !slices.Contains(jails, "sshd"):
		return false, "no sshd jail"
	}
	return true, "sshd jail"
}

// autoUpdatesOn: the updater installed and set to apply updates.
func (m *Machine) autoUpdatesOn() (bool, string) {
	switch m.Host.PkgManager {
	case "apt":
		b, _ := os.ReadFile(filepath.Join(m.Root, "/etc/apt/apt.conf.d/20auto-upgrades"))
		if m.ok("dpkg", "-s", "unattended-upgrades") && strings.Contains(string(b), `Unattended-Upgrade "1"`) {
			return true, "unattended-upgrades"
		}
		return false, "unattended-upgrades off"
	case "dnf":
		b, _ := os.ReadFile(filepath.Join(m.Root, "/etc/dnf/automatic.conf"))
		if m.ok("systemctl", "is-enabled", "--quiet", "dnf-automatic.timer") && regexp.MustCompile(`(?m)^apply_updates\s*=\s*yes`).Match(b) {
			return true, "dnf-automatic"
		}
		return false, "dnf-automatic off"
	}
	return false, "not managed for this package manager"
}

// sysctlLive: every value of vpsctl's drop-in is the live one (/proc/sys).
func (m *Machine) sysctlLive() (bool, string) {
	for _, line := range strings.Split(sysctlConf, "\n") {
		k, want, ok := strings.Cut(line, " = ")
		if !ok {
			continue
		}
		b, _ := os.ReadFile(filepath.Join(m.Root, "/proc/sys", strings.ReplaceAll(k, ".", "/")))
		if got := strings.TrimSpace(string(b)); got != want {
			return false, k + " is " + cmp.Or(got, "unreadable")
		}
	}
	return true, ""
}
