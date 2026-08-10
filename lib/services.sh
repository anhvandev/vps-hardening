#!/usr/bin/env bash
# lib/services.sh - fail2ban, automatic security updates, sysctl hardening.
#
# Error isolation: every function warns and returns 0 on failure — the SSH
# hardening already applied must never be jeopardized by a fail2ban or sysctl
# hiccup. (Firewall during a port change is the one critical path and lives in
# lib/firewall.sh.)
#
# Requires (from detect.sh): FAMILY PKG

# setup_fail2ban PORT — jail drop-in with a banaction matching the real
# firewall backend. Debian/Ubuntu >= 24.04 default to nftables; firewalld
# systems use firewallcmd-ipset.
setup_fail2ban() {
  local port=$1 banaction backend_line
  if ! command -v fail2ban-client &>/dev/null; then
    info "installing fail2ban"
    case $PKG in
      apt)
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban \
          || { warn "fail2ban install failed — skipping"; return 0; }
        ;;
      dnf)
        dnf install -y epel-release >/dev/null 2>&1 || true
        dnf install -y fail2ban \
          || { warn "fail2ban install failed (EPEL unavailable?) — skipping"; return 0; }
        ;;
      zypper)
        zypper --non-interactive install fail2ban \
          || { warn "fail2ban install failed — skipping"; return 0; }
        ;;
      pacman)
        pacman -Sy --noconfirm fail2ban \
          || { warn "fail2ban install failed — skipping"; return 0; }
        ;;
      *)
        warn "no package manager path for fail2ban (PKG=$PKG) — skipping"
        return 0
        ;;
    esac
  fi

  if systemctl is-active --quiet firewalld 2>/dev/null; then
    banaction=firewallcmd-ipset
  elif command -v nft &>/dev/null; then
    banaction=nftables-multiport
  else
    # Ubuntu 22.04's fail2ban 0.11.2 does not know nftables-*; iptables works.
    banaction=iptables-multiport
  fi
  backend_line=''
  if [[ $FAMILY != debian ]]; then
    backend_line='backend = systemd'
  elif systemctl list-unit-files rsyslog.service &>/dev/null; then
    if ! systemctl is-enabled --quiet rsyslog.service 2>/dev/null; then
      # Debian/Ubuntu cloud images have no syslog: stock file backend dies.
      backend_line='backend = systemd'
    fi
  else
    backend_line='backend = systemd'
  fi

  install -d -m 755 /etc/fail2ban/jail.d
  {
    printf '[sshd]\n'
    printf 'enabled = true\n'
    printf 'port = %s\n' "$port"
    if [[ -n $backend_line ]]; then printf '%s\n' "$backend_line"; fi
    printf 'banaction = %s\n' "$banaction"
  } > /etc/fail2ban/jail.d/00-hardening.local

  systemctl enable --now fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban >/dev/null 2>&1 || true
  sleep 2
  if fail2ban-client status sshd &>/dev/null; then
    info "fail2ban sshd jail active (banaction=$banaction)"
  else
    warn "fail2ban sshd jail not active — check 'fail2ban-client status'"
  fi
}

# setup_auto_updates — unattended-upgrades (debian) / dnf-automatic (rhel).
# suse/arch: documented skip.
setup_auto_updates() {
  case $PKG in
    apt)
      if ! dpkg -s unattended-upgrades &>/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unattended-upgrades \
          || { warn "unattended-upgrades install failed — skipping"; return 0; }
      fi
      {
        printf 'APT::Periodic::Update-Package-Lists "1";\n'
        printf 'APT::Periodic::Unattended-Upgrade "1";\n'
        printf 'APT::Periodic::AutocleanInterval "7";\n'
      } > /etc/apt/apt.conf.d/20auto-upgrades
      systemctl enable --now apt-daily.timer apt-daily-upgrade.timer \
        >/dev/null 2>&1 || true
      info "unattended-upgrades enabled"
      ;;
    dnf)
      if ! rpm -q dnf-automatic &>/dev/null; then
        dnf install -y dnf-automatic \
          || { warn "dnf-automatic install failed — skipping"; return 0; }
      fi
      sed -i 's/^apply_updates = .*/apply_updates = yes/' /etc/dnf/automatic.conf
      systemctl enable --now dnf-automatic.timer >/dev/null 2>&1 \
        || warn "dnf-automatic.timer failed to start"
      info "dnf-automatic enabled (apply_updates = yes)"
      ;;
    *)
      warn "auto security updates not managed for PKG=$PKG — skipping (documented)"
      ;;
  esac
}

# setup_sysctl — network/kernel hardening drop-in. `sysctl --system` may fail
# in containers (read-only /proc) — warn, never die.
setup_sysctl() {
  {
    printf '# Managed by vps-hardening.sh\n'
    printf 'net.ipv4.conf.all.accept_redirects = 0\n'
    printf 'net.ipv4.conf.all.send_redirects = 0\n'
    printf 'net.ipv4.conf.default.accept_source_route = 0\n'
    printf 'net.ipv4.tcp_syncookies = 1\n'
    printf 'net.ipv6.conf.all.accept_redirects = 0\n'
    printf 'kernel.kptr_restrict = 2\n'
  } > /etc/sysctl.d/90-hardening.conf
  if sysctl --system >/dev/null 2>&1; then
    info "sysctl hardening applied"
  else
    warn "sysctl --system failed (container without /proc write?) — drop-in written"
  fi
}
