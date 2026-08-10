#!/usr/bin/env bash
# lib/logging.sh - logging helpers with TTY-aware colors.
# Sourced by vps-hardening.sh under `set -euo pipefail`; must never abort the
# caller: every function returns 0 or calls die() intentionally.

# Colors only when stderr is a terminal.
if [[ -t 2 ]]; then
  _C_INFO=$'\e[32m' _C_WARN=$'\e[33m' _C_ERR=$'\e[31m' _C_RST=$'\e[0m'
else
  _C_INFO='' _C_WARN='' _C_ERR='' _C_RST=''
fi

info() { printf '%s[*]%s %s\n' "$_C_INFO" "$_C_RST" "$*" >&2; }
warn() { printf '%s[!]%s %s\n' "$_C_WARN" "$_C_RST" "$*" >&2; }
err()  { printf '%s[x]%s %s\n' "$_C_ERR"  "$_C_RST" "$*" >&2; }
die()  { err "$*"; exit 1; }

# Prompt helper: ask_yesno QUESTION [default]
# Reads from /dev/tty when available so it works under tee'd logs.
# Returns 0 on yes, 1 on no.
ask_yesno() {
  local question=$1 default=${2:-n} reply
  local hint='[y/N]'
  [[ $default == y ]] && hint='[Y/n]'
  if [[ -r /dev/tty ]]; then
    printf '%s %s ' "$question" "$hint" > /dev/tty
    read -r reply < /dev/tty
  else
    read -r reply || reply=''
  fi
  reply=${reply:-$default}
  [[ $reply =~ ^[Yy]$ ]]
}
