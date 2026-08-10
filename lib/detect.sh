#!/usr/bin/env bash
# lib/detect.sh - runtime feature detection for distro, SSH daemon model, SELinux.
#
# Sourced under `set -euo pipefail` by the orchestrator. HARD RULES:
#   - never use `cmd && VAR=x` as a bare final statement (aborts caller under -e)
#   - probe loops must be wrapped in if/then/fi or end with `|| true`
#   - this file must finish with exit status 0 on both socket and non-socket hosts

# Preflight: init system must be systemd (OpenVZ/LXC/chroot unsupported).
if [[ ! -d /run/systemd/system ]]; then
  printf 'ERROR: unsupported environment: systemd required (PID 1)\n' >&2
  return 1 2>/dev/null || exit 1
fi

# Preflight: must run as root.
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  printf 'ERROR: must run as root\n' >&2
  return 1 2>/dev/null || exit 1
fi

# Distro identity.
# shellcheck disable=SC1091
. /etc/os-release
DISTRO_ID=${ID:-unknown}

FAMILY=unknown
case " ${ID_LIKE:-} ${ID:-} " in
  *rhel*|*fedora*)     FAMILY=rhel ;;
  *suse*)              FAMILY=suse ;;
  *debian*|*ubuntu*)   FAMILY=debian ;;
  *arch*)              FAMILY=arch ;;
esac

case " ${ID:-} " in
  *" ubuntu "*|*" debian "*|*" fedora "*|*" rocky "*|*" almalinux "*|\
*" centos "*|*" rhel "*|*" opensuse "*|*" opensuse-leap "*|\
*" opensuse-tumbleweed "*|*" sles "*|*" arch "*)
    : ;;
  *)
    printf 'WARN: distro %s not in the supported set; proceeding best-effort\n' \
      "${ID:-unknown}" >&2
    ;;
esac

# SSH unit name: Debian/Ubuntu call it "ssh", everyone else "sshd".
SSH_UNIT=ssh
if [[ $FAMILY =~ ^(rhel|suse|arch)$ || ${ID:-} == fedora ]]; then
  SSH_UNIT=sshd
fi

# Socket activation: enabled-but-inactive counts too (Ubuntu 24.04+, Debian 13).
SOCKET_MODE=false
for _s in ssh.socket sshd.socket; do
  if systemctl list-unit-files "$_s" &>/dev/null; then
    if systemctl is-active --quiet "$_s" 2>/dev/null || \
       systemctl is-enabled --quiet "$_s" 2>/dev/null; then
      SOCKET_MODE=true
      SSH_SOCKET_UNIT=$_s
    fi
  fi
done
unset _s
SSH_SOCKET_UNIT=${SSH_SOCKET_UNIT:-ssh.socket}

# SELinux: anything but Disabled needs restorecon/semanage handling.
SELINUX=false
if command -v getenforce &>/dev/null; then
  if [[ $(getenforce 2>/dev/null) != Disabled ]]; then
    SELINUX=true
  fi
fi

# Admin group + package manager.
ADMIN_GROUP=sudo
if [[ $FAMILY != debian ]]; then
  ADMIN_GROUP=wheel
fi

PKG=unknown
case $FAMILY in
  debian) PKG=apt ;;
  rhel)   PKG=dnf ;;
  suse)   PKG=zypper ;;
  arch)   PKG=pacman ;;
esac

export DISTRO_ID FAMILY SSH_UNIT SOCKET_MODE SSH_SOCKET_UNIT SELINUX ADMIN_GROUP PKG

# Hard rule: sourcing must end with status 0.
return 0 2>/dev/null || true
