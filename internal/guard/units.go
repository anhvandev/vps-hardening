package guard

import (
	"errors"
	"fmt"
	"strings"
)

// UnitAction proposes a systemctl-style Verb ("stop", "disable", "edit",
// "delete", "restart", ...) on a Unit; a name without a suffix is a .service.
type UnitAction struct{ Unit, Verb string }

func init() { rules = append(rules, keepProtectedUnits, keepFail2banUnit) }

// keepFail2banUnit refuses editing or deleting fail2ban's unit: it may be
// stopped and started, never broken.
func keepFail2banUnit(_ Facts, action any) error {
	a, ok := action.(UnitAction)
	if !ok || (a.Unit != "fail2ban" && a.Unit != "fail2ban.service") || (a.Verb != "edit" && a.Verb != "delete") {
		return nil
	}
	return errors.New("refused: fail2ban.service can be stopped and started, not edited or deleted")
}

// protected maps each Protected Unit to what losing it would cut.
var protected = map[string]string{
	"ssh.service": "remote SSH access", "sshd.service": "remote SSH access",
	"ssh.socket": "remote SSH access", "sshd.socket": "remote SSH access",
	"ufw.service": "the firewall", "firewalld.service": "the firewall",
	"networking.service": "networking", "systemd-networkd.service": "networking",
	"NetworkManager.service":   "networking",
	"systemd-resolved.service": "name resolution",
	"cloud-init.service":       "cloud-init", "cloud-init-local.service": "cloud-init",
	"cloud-init-main.service": "cloud-init", "cloud-init-network.service": "cloud-init",
	"cloud-config.service": "cloud-init", "cloud-final.service": "cloud-init",
}

// keepProtectedUnits refuses stopping, disabling, editing or deleting a
// Protected Unit, and restarting ssh (a failed restart drops remote access).
func keepProtectedUnits(_ Facts, action any) error {
	a, ok := action.(UnitAction)
	if !ok {
		return nil
	}
	unit := a.Unit
	if !strings.Contains(unit, ".") {
		unit += ".service"
	}
	what, ok := protected[unit]
	switch {
	case !ok:
		return nil
	case a.Verb == "stop", a.Verb == "disable", a.Verb == "edit", a.Verb == "delete",
		a.Verb == "restart" && what == "remote SSH access":
		return fmt.Errorf("refused: %s is a Protected Unit (%s), cannot %s it", unit, what, a.Verb)
	}
	return nil
}
