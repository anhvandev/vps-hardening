package user

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// InstallKey makes sure name holds an SSH key someone actually has: it
// generates an ed25519 pair, shows the private half once (written to keyOut
// with mode 600, or printed on the controlling TTY when keyOut is "", then,
// with waitSaved, held until the operator types `saved`) and
// installs the public half as the user's authorized_keys. A key vpsctl already
// emitted is kept; a key it never emitted is refused unless rotate.
func (m *Manager) InstallKey(name, keyOut string, rotate, waitSaved bool) error {
	pw, exists, err := m.Lookup(name)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("user %q does not exist", name)
	}
	sshDir := filepath.Join(m.Root, pw.Home, ".ssh")
	marker := filepath.Join(m.Root, "/var/lib/vpsctl", "key-emitted-"+name)
	if !rotate {
		if fi, err := os.Stat(filepath.Join(sshDir, "authorized_keys")); err == nil && fi.Size() > 0 {
			if _, err := os.Stat(marker); err == nil {
				return nil
			}
			return fmt.Errorf("key for %q exists but was never emitted by vpsctl; re-run with --rotate-key", name)
		}
	}

	// Open the destination first: no TTY → fail before anything is generated.
	out, err := m.openKeyOut(keyOut)
	if err != nil {
		return err
	}
	defer out.Close()

	tmp, err := os.MkdirTemp(m.TmpDir, "vpsctl-key-") // mode 700
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	key := filepath.Join(tmp, "key")
	if err := m.run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "vpsctl-"+name, "-f", key); err != nil {
		return err
	}
	priv, err := os.ReadFile(key)
	if err != nil {
		return err
	}
	pub, err := os.ReadFile(key + ".pub")
	if err != nil {
		return err
	}

	// Emit before installing: a key nobody received must never become the only way in.
	if keyOut == "" {
		priv = fmt.Appendf(nil, "\n==== PRIVATE KEY for %s (shown ONCE, save it now) ====\n%s==== END ====\n", name, priv)
	}
	if _, err := out.Write(priv); err != nil {
		return fmt.Errorf("emit private key: %w", err)
	}
	if keyOut == "" && waitSaved {
		if err := waitForSaved(out); err != nil {
			return err
		}
	}

	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(sshDir, 0o700); err != nil {
		return err
	}
	if err := os.Chown(sshDir, pw.UID, pw.GID); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(sshDir, "authorized_keys"), pub, 0o600, func(tmp string) error {
		return os.Chown(tmp, pw.UID, pw.GID)
	}); err != nil {
		return err
	}
	// SELinux: a wrong context on .ssh silently breaks key auth.
	if m.Host.SELinux {
		if err := m.run("restorecon", "-R", sshDir); err != nil {
			return err
		}
	}

	if err := os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
		return err
	}
	return os.WriteFile(marker, nil, 0o600)
}

// waitForSaved re-prompts on tty until the operator types `saved`; EOF or a
// read error means the key may not be stored, so it aborts.
func waitForSaved(tty io.ReadWriter) error {
	in := bufio.NewReader(tty)
	for {
		if _, err := fmt.Fprint(tty, "Type 'saved' once the private key is stored safely: "); err != nil {
			return err
		}
		line, err := in.ReadString('\n')
		if strings.TrimSpace(line) == "saved" {
			return nil
		}
		if err != nil {
			return fmt.Errorf("private key not confirmed saved: %w", err)
		}
	}
}

// openKeyOut opens where the private key goes: keyOut (mode 600) or the TTY.
func (m *Manager) openKeyOut(keyOut string) (io.ReadWriteCloser, error) {
	if keyOut != "" {
		f, err := os.OpenFile(keyOut, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return nil, err
		}
		if err := f.Chmod(0o600); err != nil { // pre-existing file may be looser
			f.Close()
			return nil, err
		}
		return f, nil
	}
	open := m.OpenTTY
	if open == nil {
		open = func() (io.ReadWriteCloser, error) { return os.OpenFile("/dev/tty", os.O_RDWR, 0) }
	}
	tty, err := open()
	if err != nil {
		return nil, errors.Join(errors.New("no controlling TTY to show the private key; re-run with --key-out PATH"), err)
	}
	return tty, nil
}
