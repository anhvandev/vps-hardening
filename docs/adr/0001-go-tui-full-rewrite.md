# Full rewrite in Go with a bubbletea TUI; the bash script is retired

The tool grows from a one-shot hardening script into an ongoing VPS management TUI (firewall, users, services, SSH, fail2ban, cron). We rewrote everything in Go (bubbletea) as a single static binary and deleted the bash implementation instead of wrapping it, because a polished TUI was a requirement from day one and driving sourced bash libs (`die` exits, implicit globals, errors only as stderr text) made clean error display and rollback from Go impractical.

## Consequences

- The lockout-safety invariants proven in the bash version (open new SSH port before closing the old, verify gate, pre-lock assertions, snapshot rollback) must be re-established as Go tests plus the container matrix — they are not inherited.
- Distribution needs a release pipeline: prebuilt `linux-amd64`/`linux-arm64` binaries, sha256-verified by `install.sh`.
