#!/usr/bin/env bash
# install.sh - one-command bootstrap for vps-hardening.
#
# Downloads the release tarball pinned by VPS_HARDENING_REF (a git tag or
# branch), extracts it to a temp dir, then hands off to vps-hardening.sh with
# all arguments forwarded verbatim. Contains no hardening logic itself.
#
# Usage (one-liner):
#   curl -fsSL https://raw.githubusercontent.com/anhvandev/vps-hardening/v1.0.0/install.sh \
#     | sudo bash -s -- --user myname [--port 2222] [--yes] ...
#
# Overrides (env vars):
#   VPS_HARDENING_REPO   owner/name (default: anhvandev/vps-hardening)
#   VPS_HARDENING_REF    git tag/branch to fetch (default: v1.0.0)
#
# Requires: curl or wget, tar, gzip — present on every mainstream cloud image.
set -euo pipefail

REPO=${VPS_HARDENING_REPO:-anhvandev/vps-hardening}
REF=${VPS_HARDENING_REF:-v1.0.0}
TARBALL_URL="https://github.com/${REPO}/archive/refs/tags/${REF}.tar.gz"
if [[ ${REF} != v* || ${REF} == *..* ]]; then
  # Non-tag ref (branch/SHA) lives under heads/, and reject path-traversal-ish refs.
  [[ ${REF} == *..* ]] && { echo "ERROR: invalid ref: ${REF}" >&2; exit 2; }
  TARBALL_URL="https://github.com/${REPO}/archive/refs/heads/${REF}.tar.gz"
fi

die() { echo "install.sh: ERROR: $*" >&2; exit 1; }

# Fresh VPS images usually lack git but always ship curl (or wget) + tar.
if command -v curl &>/dev/null; then
  fetch() { curl -fsSL "$1"; }
elif command -v wget &>/dev/null; then
  fetch() { wget -qO- "$1"; }
else
  die "neither curl nor wget found; install one first (e.g. apt-get install -y curl)"
fi
command -v tar &>/dev/null || die "tar not found"

# Root is required — the hardening script will enforce it too, but fail early.
[[ ${EUID} -eq 0 ]] || die "must run as root (use: ... | sudo bash -s -- --user NAME)"

tmpdir=$(mktemp -d /tmp/vps-hardening.XXXXXX)
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT

echo "install.sh: fetching ${REPO}@${REF}"
fetch "${TARBALL_URL}" | tar -xz -C "$tmpdir" || die "download/extract failed (tag ${REF} exists on github.com/${REPO}?)"

# GitHub names the top dir "<repo>-<ref-without-leading-v>" for tags and
# "<repo>-<ref>" for branches — resolve it from the tarball instead of
# reimplementing that mapping.
topdir=$(find "$tmpdir" -mindepth 1 -maxdepth 1 -type d | head -1)
script="${topdir}/vps-hardening.sh"
[[ -f ${script} ]] || die "vps-hardening.sh missing in tarball (repo layout changed?)"

# exec so the hardening script owns the tty for its interactive verify gate.
echo "install.sh: handing off to vps-hardening.sh $*"
exec bash "$script" "$@"
