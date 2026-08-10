#!/usr/bin/env bash
# lib/firewall.sh - ufw / firewalld management with open/close split.
#
# Lockout rule: firewall_open_ssh only ADDS the new port (called BEFORE the
# sshd apply). firewall_close_old_ssh removes the old port ONLY after the new
# listener is verified. Arch has no managed firewall — documented skip.
#
# Requires (from detect.sh): FAMILY PKG

# firewall_active_backend — prints ufw|firewalld|none.
firewall_active_backend() {
  case $FAMILY in
    debian)     printf 'ufw\n' ;;
    rhel|suse)  printf 'firewalld\n' ;;
    *)          printf 'none\n' ;;
  esac
}

# firewall_setup PORT — UNCONDITIONAL: install, enable, allow the SSH port.
# Called even on runs without --port so a default run still ends firewalled.
firewall_setup() {
  local port=$1 backend
  backend=$(firewall_active_backend)
  case $backend in
    ufw)
      if ! command -v ufw &>/dev/null; then
        info "installing ufw"
        DEBIAN_FRONTEND=noninteractive apt-get update -qq \
          || warn "apt-get update failed"
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw \
          || die "failed to install ufw"
      fi
      # Always allow BEFORE enabling — enabling first can cut the live session.
      ufw allow "$port/tcp" >/dev/null || die "ufw allow $port/tcp failed"
      if ufw status | grep -qi 'status: *active'; then
        info "ufw already active"
      else
        ufw --force enable >/dev/null || die "ufw enable failed"
        info "ufw enabled (allowing $port/tcp)"
      fi
      ;;
    firewalld)
      if ! command -v firewall-cmd &>/dev/null; then
        info "installing firewalld"
        case $PKG in
          dnf)    dnf install -y firewalld || die "failed to install firewalld" ;;
          zypper) zypper --non-interactive install firewalld \
                    || die "failed to install firewalld" ;;
          *)      die "no package manager path for firewalld (PKG=$PKG)" ;;
        esac
      fi
      if ! systemctl is-active --quiet firewalld; then
        systemctl enable --now firewalld || die "failed to start firewalld"
      fi
      firewall-cmd --permanent --add-port="$port/tcp" >/dev/null \
        || die "firewalld: failed to open $port/tcp"
      firewall-cmd --reload >/dev/null || die "firewall-cmd --reload failed"
      info "firewalld active (allowing $port/tcp)"
      ;;
    none)
      warn "no managed firewall for family '$FAMILY' — skipping (documented)"
      ;;
  esac
}

# firewall_open_ssh NEW_PORT — port-change path only; opens the new port
# BEFORE apply_sshd. Never closes anything here.
firewall_open_ssh() {
  local port=$1 backend
  backend=$(firewall_active_backend)
  case $backend in
    ufw)
      ufw allow "$port/tcp" >/dev/null || die "ufw allow $port/tcp failed"
      ;;
    firewalld)
      firewall-cmd --permanent --add-port="$port/tcp" >/dev/null \
        || die "firewalld: failed to open $port/tcp"
      firewall-cmd --reload >/dev/null || die "firewall-cmd --reload failed"
      ;;
    none)
      return 0
      ;;
  esac
  info "firewall: opened new SSH port $port (old port still open)"
}

# firewall_close_old_ssh OLD_PORT NEW_PORT — called ONLY after the new
# listener is verified. Removes the old SSH port/service and any stale rules.
firewall_close_old_ssh() {
  local old_port=$1 new_port=$2 backend stale
  [[ $old_port == "$new_port" ]] && return 0
  backend=$(firewall_active_backend)
  case $backend in
    ufw)
      ufw delete allow "$old_port/tcp" >/dev/null 2>&1 || true
      # Purge stale allow rules for any other SSH-ish port except the new one.
      # `ufw status` prints v6 duplicates as "PORT/tcp (v6)" — strip the suffix
      # and delete both families.
      while read -r stale; do
        if [[ -n $stale && $stale != "$new_port" ]]; then
          ufw delete allow "$stale/tcp" >/dev/null 2>&1 || true
        fi
      done < <(ufw status 2>/dev/null \
               | awk '/ALLOW/ {sub(/ \(v6\)$/,"",$1); print $1}' \
               | awk -F/ '$2=="tcp" {print $1}' | grep -E '^[0-9]+$' || true)
      ;;
    firewalld)
      firewall-cmd --permanent --remove-service=ssh >/dev/null 2>&1 || true
      firewall-cmd --permanent --remove-port="$old_port/tcp" >/dev/null 2>&1 || true
      firewall-cmd --reload >/dev/null || die "firewall-cmd --reload failed"
      ;;
    none)
      return 0
      ;;
  esac
  info "firewall: closed old SSH port $old_port"
}
