package user

import (
	"fmt"
	"strconv"
	"strings"
)

// ManagedUsers names the Managed Users: UID ≥ 1000 (not nobody) with a login shell.
func (m *Manager) ManagedUsers() ([]string, error) {
	res, err := m.R.Run("getent", "passwd")
	if err == nil && res.Code != 0 {
		err = fmt.Errorf("exit %d", res.Code)
	}
	if err != nil {
		return nil, fmt.Errorf("getent passwd: %w", err)
	}
	var names []string
	for _, line := range strings.Split(res.Stdout, "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		shell := f[6]
		if err != nil || uid < 1000 || uid == 65534 || strings.HasSuffix(shell, "/nologin") || strings.HasSuffix(shell, "/false") {
			continue
		}
		names = append(names, f[0])
	}
	return names, nil
}
