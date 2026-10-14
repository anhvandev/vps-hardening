#!/usr/bin/env bash
# tests/test-install.sh - run install.sh against a fake local release (file://)
# and check: good checksum installs + forwards args, bad checksum fails closed.
# Usage: bash tests/test-install.sh   (no root, no network)
set -euo pipefail
cd "$(dirname "$0")/.."

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

case $(uname -m) in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) echo "unsupported test host arch" >&2; exit 1 ;;
esac

# Fake release: a "vpsctl" that echoes its args, plus matching sums.
rel=$work/rel/v9.9.9
mkdir -p "$rel"
printf '#!/bin/sh\necho "fake-vpsctl $*"\n' > "$rel/vpsctl-linux-$arch"
(cd "$rel" && sha256sum "vpsctl-linux-$arch" > sha256sums.txt)

run() {
  VPSCTL_VERSION=v9.9.9 VPSCTL_BASE_URL="file://$work/rel" VPSCTL_BIN_DIR="$work/bin" \
    bash install.sh "$@"
}
fail() { echo "[install] FAIL: $*" >&2; exit 1; }

# 1) good checksum: installs 0755 and execs `vpsctl harden ARGS`.
mkdir -p "$work/bin"
out=$(run --user bob) || fail "install with valid checksum exited non-zero"
[[ $out == *"fake-vpsctl harden --user bob"* ]] || fail "args not forwarded to harden: $out"
[[ $(stat -c %a "$work/bin/vpsctl") == 755 ]] || fail "binary not installed 0755"
echo "[install] OK: valid checksum installs and forwards args"

# 2) tampered binary: must fail and leave the installed binary untouched.
echo "tampered" >> "$rel/vpsctl-linux-$arch"
before=$(sha256sum "$work/bin/vpsctl")
if run >/dev/null 2>&1; then fail "install succeeded with checksum mismatch"; fi
[[ $(sha256sum "$work/bin/vpsctl") == "$before" ]] || fail "binary replaced despite mismatch"
echo "[install] OK: checksum mismatch fails closed"

# 3) asset missing from sums: must fail (no entry = no trust).
: > "$rel/sha256sums.txt"
if run >/dev/null 2>&1; then fail "install succeeded with no checksum entry"; fi
echo "[install] OK: missing checksum entry fails closed"
