# Release pipeline + install.sh

Status: resolved
Milestone: M1
Blocked by: 01

## What
- GitHub Actions on `v*` tag: `go test`, build `CGO_ENABLED=0` `linux-amd64` + `linux-arm64`, publish binaries + `sha256sums.txt` to the release.
- `install.sh`: pick arch (`uname -m`), download binary + sums for `VPSCTL_VERSION` (default: pinned tag), verify sha256 (fail closed), install `/usr/local/bin/vpsctl` 0755; if args are given, `exec vpsctl harden "$@"`.

## Comments

Resolved on `vpsctl-go-rewrite` @ 940ccd2. Default pinned tag `v2.0.0` (bump per release); assets `vpsctl-linux-{amd64,arm64}` + `sha256sums.txt`.
