#!/usr/bin/env bash
# tests/test-container.sh - systemd container matrix for vps-hardening.sh.
#
# Usage:
#   bash tests/test-container.sh                 # full matrix
#   bash tests/test-container.sh ubuntu-24.04    # single image
#
# Requires docker. Containers run privileged (systemd + firewall backends).
# Every container is force-removed at the end of its run — no orphans.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

# name:port|'' (empty = default port run)
MATRIX=(
  "ubuntu-22.04:"
  "ubuntu-24.04:2222"
  "debian-12:"
  "debian-13:2222"
  "rockylinux-9:"
  "rockylinux-8:"
)
if [[ $# -gt 0 ]]; then
  MATRIX=("$1:${2:-}")
fi

pass=0; fail=0; FAILED=()
log() { printf '\033[36m[matrix]\033[0m %s\n' "$*"; }

for entry in "${MATRIX[@]}"; do
  name=${entry%%:*}
  port=${entry#*:}
  image=vh-test-$name
  ctr=vh-run-$name-$$
  log "=== $name (port: ${port:-default}) ==="

  docker build -q -f "tests/Dockerfile.$name" -t "$image" . >/dev/null \
    || { log "BUILD FAIL: $name"; fail=$((fail+1)); FAILED+=("$name(build)"); continue; }

  docker rm -f "$ctr" >/dev/null 2>&1
  docker run -d --name "$ctr" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "$PWD:/src:ro" "$image" >/dev/null

  x() { docker exec "$ctr" bash -c "$*"; }
  ok()  { log "  OK: $1"; }
  bad() { log "  FAIL: $1"; fail=$((fail+1)); FAILED+=("$name: $1"); }

  # wait for systemd
  for _try in $(seq 1 30); do
    x 'systemctl is-system-running 2>/dev/null | grep -qE "running|degraded"' && break
    sleep 1
  done

  # Pre-state socket assertions: socket distros must really be in socket mode.
  case $name in
    ubuntu-24.04|debian-13)
      x 'systemctl is-enabled --quiet ssh.socket' \
        && ok "pre-state: ssh.socket enabled" \
        || bad "pre-state: ssh.socket NOT enabled (test would not exercise socket path)"
      x 'systemctl is-active --quiet ssh.socket' \
        && ok "pre-state: ssh.socket active" \
        || bad "pre-state: ssh.socket NOT active"
      ;;
  esac

  portarg=()
  [[ -n $port ]] && portarg=(--port "$port")

  # Run 1: full hardening.
  x "cd /src && bash vps-hardening.sh --user testop --yes --key-out /root/k ${portarg[*]:-}" \
    > "/tmp/vh-$name-run1.log" 2>&1
  rc=$?
  [[ $rc == 0 ]] && ok "run 1 exit 0" || { bad "run 1 exit $rc (see /tmp/vh-$name-run1.log)"; docker rm -f "$ctr" >/dev/null; continue; }

  EPORT=${port:-22}

  # SSH effective config assertions (also proves 00- beats 50-cloud-init.conf).
  # Note: capture sshd -T output before grepping — piping into grep -q kills
  # sshd with SIGPIPE and can false-fail.
  x "out=\$(sshd -T) && grep -qx 'passwordauthentication no' <<< \"\$out\"" \
    && ok "passwordauthentication no" || bad "passwordauthentication not no"
  x "out=\$(sshd -T) && grep -Eqx '(kbdinteractiveauthentication|challengeresponseauthentication) no' <<< \"\$out\"" \
    && ok "kbd-interactive no" || bad "kbd-interactive not disabled"
  x "out=\$(sshd -T) && grep -qx 'permitrootlogin no' <<< \"\$out\"" \
    && ok "permitrootlogin no" || bad "permitrootlogin not no"
  x "out=\$(sshd -T) && grep -qx 'port $EPORT' <<< \"\$out\"" \
    && ok "effective port $EPORT" || bad "effective port != $EPORT"
  x "out=\$(sshd -T -C user=testop,host=localhost,addr=127.0.0.1) && grep -qx 'pubkeyauthentication yes' <<< \"\$out\"" \
    && ok "-C probe pubkey yes" || bad "-C probe failed"

  # Listener assertions (field-exact).
  x "test -n \"\$(ss -ltnH 'sport = :$EPORT')\"" \
    && ok "listener on $EPORT" || bad "no listener on $EPORT"
  if [[ -n $port ]]; then
    x "test -z \"\$(ss -ltnH 'sport = :22')\"" \
      && ok "port 22 closed after port change" || bad "port 22 still listening"
  fi

  # User assertions.
  x 'id testop' >/dev/null && ok "user testop exists" || bad "user testop missing"
  x 'groups testop | grep -qE "sudo|wheel"' \
    && ok "testop in admin group" || bad "testop not in admin group"
  x "ssh -i /root/k -p $EPORT -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=5 testop@localhost true" \
    && ok "key login works" || bad "key login FAILED"

  # Firewall assertions (skip families without a managed backend).
  case $name in
    ubuntu-*|debian-*)
      x 'ufw status | grep -q "Status: active"' \
        && ok "ufw active" || bad "ufw not active"
      x "ufw status | grep -q '$EPORT/tcp'" \
        && ok "ufw allows $EPORT" || bad "ufw missing $EPORT"
      if [[ -n $port ]]; then
        x 'ufw status | grep -q "^22/tcp"' \
          && bad "ufw still allows 22" || ok "ufw port 22 closed"
      fi
      ;;
    rockylinux-*)
      x 'systemctl is-active --quiet firewalld' \
        && ok "firewalld active" || bad "firewalld not active"
      x "firewall-cmd --list-all | grep -q '$EPORT/tcp'" \
        && ok "firewalld allows $EPORT" || bad "firewalld missing $EPORT"
      ;;
  esac

  # fail2ban: jail active + functional ban materializes in the firewall backend.
  x 'fail2ban-client status sshd' >/dev/null \
    && ok "fail2ban sshd jail active" || bad "fail2ban jail not active"
  x 'fail2ban-client set sshd banip 203.0.113.1' >/dev/null 2>&1
  sleep 2
  banned=0
  x 'nft list ruleset 2>/dev/null | grep -q 203.0.113.1' >/dev/null && banned=1
  x 'iptables -L -n 2>/dev/null | grep -q 203.0.113.1' >/dev/null && banned=1
  x 'ipset list 2>/dev/null | grep -q 203.0.113.1' >/dev/null && banned=1
  x 'firewall-cmd --get-ipsets 2>/dev/null | grep -qw f2b-sshd && firewall-cmd --ipset=f2b-sshd --get-entries 2>/dev/null | grep -q 203.0.113.1' >/dev/null && banned=1
  x 'firewall-cmd --get-ipsets 2>/dev/null | grep -qw fail2ban-sshd && firewall-cmd --ipset=fail2ban-sshd --get-entries 2>/dev/null | grep -q 203.0.113.1' >/dev/null && banned=1
  [[ $banned == 1 ]] && ok "functional ban materialized" || bad "ban IP not in firewall backend"
  x 'fail2ban-client set sshd unbanip 203.0.113.1' >/dev/null 2>&1

  # Auto-updates.
  case $name in
    ubuntu-*|debian-*)
      x 'systemctl is-enabled --quiet apt-daily-upgrade.timer' \
        && ok "unattended-upgrades timer" || bad "apt-daily-upgrade.timer missing"
      ;;
    rockylinux-*)
      x 'systemctl is-enabled --quiet dnf-automatic.timer' \
        && ok "dnf-automatic timer" || bad "dnf-automatic.timer missing"
      ;;
  esac

  # sysctl (best effort — container /proc may block some keys).
  x 'sysctl -n net.ipv4.tcp_syncookies 2>/dev/null | grep -q 1' \
    && ok "tcp_syncookies=1" || log "  note: tcp_syncookies not applied (container /proc limit)"

  # Log safety: private key must never hit the log.
  if x 'grep -s "PRIVATE KEY" /var/log/vps-hardening-*.log' >/dev/null; then
    bad "private key found in log"
  else
    ok "log free of private key"
  fi

  # Idempotency: run 2 must exit 0.
  x "cd /src && bash vps-hardening.sh --user testop --yes --key-out /root/k ${portarg[*]:-}" \
    > "/tmp/vh-$name-run2.log" 2>&1
  rc=$?
  [[ $rc == 0 ]] && ok "run 2 idempotent exit 0" || bad "run 2 exit $rc"

  # Flagless re-run must NOT revert a custom port.
  if [[ -n $port ]]; then
    x "cd /src && bash vps-hardening.sh --user testop --yes --key-out /root/k" \
      > "/tmp/vh-$name-run3.log" 2>&1
    rc=$?
    if [[ $rc == 0 ]]; then
      x "sshd -T | grep -qx 'port $port'" \
        && ok "flagless re-run kept port $port" || bad "flagless re-run REVERTED port"
    else
      bad "flagless re-run exit $rc"
    fi
  fi

  docker rm -f "$ctr" >/dev/null 2>&1
  docker ps -a --format '{{.Names}}' | grep -q "^$ctr\$" && bad "container orphan: $ctr"
  log "=== $name done ==="
done

log "pass-groups: $pass, failures: ${#FAILED[@]}"
if [[ ${#FAILED[@]} -gt 0 ]]; then
  printf 'FAILED: %s\n' "${FAILED[@]}"
  exit 1
fi
log "ALL CONTAINER TESTS PASSED"
