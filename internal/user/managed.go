package user

import "fmt"

// CreateUser creates the Managed User name, key-only (never a password) and
// without sudo. Names are checked as for the Admin User; existing names are
// refused.
func (m *Manager) CreateUser(name string) error {
	_, exists, err := m.checkName("user", name)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("user %q already exists", name)
	}
	return m.addUser(name)
}
