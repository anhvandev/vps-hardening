package harden

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// RecordPath holds the Hardening Record.
const RecordPath = "/var/lib/vpsctl/hardening.json"

// Record is the Hardening Record: what the machine can't tell about the last
// Hardening run. Step ids are those of Status. It never holds secrets.
type Record struct {
	Ran     time.Time            `json:"ran"`
	By      string               `json:"by"` // the operator
	Admin   string               `json:"admin_user"`
	Skipped []string             `json:"skipped,omitempty"` // steps the operator chose to skip
	Applied map[string]time.Time `json:"applied,omitempty"` // when each step was last applied
}

// LoadRecord reads the Record under root; nil, nil when there is none.
func LoadRecord(root string) (*Record, error) {
	b, err := os.ReadFile(filepath.Join(root, RecordPath))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Save replaces the Record under root atomically (temp file + rename).
func (r Record) Save(root string) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	p := filepath.Join(root, RecordPath)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p), ".hardening-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // no-op after the rename
	_, err = f.Write(append(b, '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), p)
}

// SaveRecord saves r under the machine's root.
func (m *Machine) SaveRecord(r Record) error { return r.Save(m.Root) }
