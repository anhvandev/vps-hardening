# Go skeleton, command runner, detection

Status: resolved
Milestone: M1

## What
- Go module `github.com/anhvandev/vpsctl`, `cmd/vpsctl/main.go`. Subcommands via stdlib `flag`: (none) → TUI placeholder, `harden`, `version`.
- Mockable command runner (run cmd → stdout, stderr, exit code) used by all system access; fake runner for tests.
- Detection: distro ID/family (debian|rhel), SSH unit (`ssh`/`sshd`), socket mode (+ actual socket unit), SELinux, admin group (`sudo`/`wheel`), package manager (apt/dnf). Preflight: root + systemd PID 1, else clean error. Unsupported distro → warn, best-effort.

## Acceptance
- `go test ./...` passes without root; detection tested against fixture `/etc/os-release` + fake runner for Ubuntu 22.04/24.04, Debian 12/13, Rocky 8/9.
- Socket mode detected when the socket is enabled-but-inactive.

## Comments

Resolved on `vpsctl-go-rewrite` @ d68ddeb (runner + detection in `internal/system`).
