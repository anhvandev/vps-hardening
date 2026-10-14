#!/usr/bin/env bash
# install.sh - install the vpsctl binary from a GitHub release.
#
# Downloads vpsctl-linux-<arch> + sha256sums.txt for VPSCTL_VERSION, verifies
# the checksum (fails closed), installs to /usr/local/bin/vpsctl (0755).
# With arguments, then runs `vpsctl harden ARGS...`.
#
# Usage (one-liner):
#   curl -fsSL https://raw.githubusercontent.com/anhvandev/vpsctl/v2.0.0/install.sh \
#     | sudo bash -s -- --user myname [--port 2222] [--yes] ...
#
# Overrides (env vars):
#   VPSCTL_VERSION   release tag (default: v2.0.0)
#   VPSCTL_BASE_URL  release download base (default: GitHub releases)
#   VPSCTL_BIN_DIR   install dir (default: /usr/local/bin)
#
# Requires: curl or wget, sha256sum.
set -euo pipefail

VERSION=${VPSCTL_VERSION:-v2.0.0}
BASE_URL=${VPSCTL_BASE_URL:-https://github.com/anhvandev/vpsctl/releases/download}
BIN_DIR=${VPSCTL_BIN_DIR:-/usr/local/bin}

die() { echo "install.sh: ERROR: $*" >&2; exit 1; }

case $(uname -m) in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) die "unsupported architecture: $(uname -m) (need x86_64 or aarch64)" ;;
esac
asset=vpsctl-linux-${arch}

if command -v curl &>/dev/null; then
  fetch() { curl -fsSL -o "$2" "$1"; }
elif command -v wget &>/dev/null; then
  fetch() { wget -qO "$2" "$1"; }
else
  die "neither curl nor wget found; install one first (e.g. apt-get install -y curl)"
fi
command -v sha256sum &>/dev/null || die "sha256sum not found"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "install.sh: fetching vpsctl ${VERSION} (${arch})"
fetch "${BASE_URL}/${VERSION}/${asset}" "$tmp/$asset" || die "download failed (release ${VERSION} exists?)"
fetch "${BASE_URL}/${VERSION}/sha256sums.txt" "$tmp/sums" || die "checksum download failed"

# Fail closed: no entry for our asset, or any mismatch, aborts before install.
want=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/sums")
[[ -n $want ]] || die "no checksum for ${asset} in sha256sums.txt"
got=$(sha256sum "$tmp/$asset" | cut -d' ' -f1)
[[ $got == "$want" ]] || die "checksum mismatch for ${asset} (want ${want}, got ${got})"

install -m 0755 "$tmp/$asset" "${BIN_DIR}/vpsctl" || die "cannot install to ${BIN_DIR} (run as root)"
echo "install.sh: installed ${BIN_DIR}/vpsctl ${VERSION}"

if [[ $# -gt 0 ]]; then
  rm -rf "$tmp" # exec skips the EXIT trap
  # exec so vpsctl owns the tty for its interactive verify gate.
  exec "${BIN_DIR}/vpsctl" harden "$@"
fi
