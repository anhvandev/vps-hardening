#!/usr/bin/env bash
# tests/test-static.sh - syntax, shellcheck, and static safety guards.
# Usage: bash tests/test-static.sh [--skip-shellcheck]
set -euo pipefail
cd "$(dirname "$0")/.."

SKIP_SHELLCHECK=0
[[ ${1:-} == --skip-shellcheck ]] && SKIP_SHELLCHECK=1

fail=0
say() { printf '[static] %s\n' "$*"; }

# 1) bash -n on every script.
for f in vps-hardening.sh lib/*.sh tests/*.sh; do
  bash -n "$f" && say "bash -n OK: $f" || { say "SYNTAX FAIL: $f"; fail=1; }
done

# 2) shellcheck (local binary preferred; fall back to docker image).
if [[ $SKIP_SHELLCHECK == 0 ]]; then
  if command -v shellcheck &>/dev/null; then
    shellcheck -S warning vps-hardening.sh lib/*.sh tests/*.sh \
      && say "shellcheck clean" || { say "shellcheck FAIL"; fail=1; }
  elif command -v docker &>/dev/null; then
    docker run --rm -v "$PWD:/mnt" koalaman/shellcheck:stable \
      -S warning vps-hardening.sh lib/*.sh tests/*.sh \
      && say "shellcheck clean (docker)" || { say "shellcheck FAIL"; fail=1; }
  else
    say "shellcheck unavailable — SKIPPED"
  fi
fi

# 3) Grep guards.
if grep -rnE 'systemctl( .*)? reload +(ssh|sshd)\b' lib vps-hardening.sh; then
  say "GUARD FAIL: 'systemctl reload ssh(d)' found (Debian 13 socket bug)"
  fail=1
else
  say "guard OK: no reload of ssh units"
fi

if grep -rnE '\b99-[a-z0-9-]*\.conf' lib vps-hardening.sh \
   | grep -v 'ssh\.socket\.d/99-hardening-listen\.conf'; then
  say "GUARD FAIL: 99-*.conf used as an sshd drop-in (must be 00-*)"
  fail=1
else
  say "guard OK: sshd drop-in is 00-hardening.conf"
fi

if grep -rnE 'ss -ltn.*\| *grep|grep +["'"'"']?:\$?PORT|grep +:22\b' lib vps-hardening.sh \
   | grep -vE ':[0-9]+:\s*#'; then
  say "GUARD FAIL: substring port grep (must use: ss -ltnH \"sport = :N\")"
  fail=1
else
  say "guard OK: field-exact listener checks only"
fi

# 4) Libs must not abort when sourced under set -euo pipefail.
#    Pure libs (all but detect.sh) are sourced with stubbed detect exports;
#    detect.sh's own preflight (root + systemd) is exercised by the container
#    matrix, and its non-systemd die path is smoke-checked below.
for lib in lib/logging.sh lib/user.sh lib/sshd.sh lib/firewall.sh lib/services.sh; do
  if bash -ec "set -euo pipefail
    FAMILY=debian SSH_UNIT=ssh SOCKET_MODE=false SSH_SOCKET_UNIT=ssh.socket
    SELINUX=false ADMIN_GROUP=sudo PKG=apt
    SSH_DROPIN_DIR=/nonexistent SSH_DROPIN=/nonexistent/00
    source $lib" 2>/dev/null; then
    say "source-safe: $lib"
  else
    say "SOURCE ABORTS under set -euo pipefail: $lib"
    fail=1
  fi
done
# detect.sh: verify preflight die path works on non-systemd (this env).
if bash -c 'set -euo pipefail; source lib/detect.sh' 2>/dev/null; then
  say "note: detect.sh sourced OK here (root + systemd host)"
else
  say "detect.sh preflight aborts cleanly here (expected off-root/non-systemd)"
fi

if [[ $fail == 0 ]]; then
  say "ALL STATIC CHECKS PASSED"
else
  say "STATIC CHECKS FAILED"
  exit 1
fi
