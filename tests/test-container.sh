#!/usr/bin/env bash
# tests/test-container.sh - systemd container matrix for the Go `vpsctl` binary.
#
# Usage:
#   bash tests/test-container.sh                 # full matrix
#   bash tests/test-container.sh ubuntu-24.04    # single image (default first-run port)
#   bash tests/test-container.sh debian-12 2222  # single image, first run with --port
#
# Builds a static vpsctl (CGO_ENABLED=0) and mounts it read-only into each
# privileged systemd container. Logs: /tmp/vpsctl-<name>-<step>.log.
# Every container is force-removed at the end of its run.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

GO=${GO:-/usr/local/go/bin/go}

# name:port|'' (empty = first run keeps port 22)
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

log() { printf '\033[36m[matrix]\033[0m %s\n' "$*"; }

BIN=$(mktemp -d)/vpsctl
CGO_ENABLED=0 "$GO" build -o "$BIN" ./cmd/vpsctl || { log "BUILD FAIL: vpsctl"; exit 1; }

FAILED=()
CTRS=()
trap 'for c in "${CTRS[@]}"; do docker rm -f "$c" >/dev/null 2>&1; done; rm -rf "$(dirname "$BIN")"' EXIT

# start NAME → starts a systemd container from $image and waits for boot.
start() {
  docker rm -f "$1" >/dev/null 2>&1
  CTRS+=("$1")
  docker run -d --name "$1" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "$BIN:/usr/local/bin/vpsctl:ro" "$image" >/dev/null || return 1
  for _try in $(seq 1 30); do
    docker exec "$1" bash -c 'systemctl is-system-running 2>/dev/null | grep -qE "running|degraded"' && return 0
    sleep 1
  done
}

for entry in "${MATRIX[@]}"; do
  name=${entry%%:*}
  port=${entry#*:}
  image=vpsctl-test-$name
  ctr=vpsctl-run-$name-$$
  log "=== $name (first-run port: ${port:-keep}) ==="

  docker build -q -t "$image" - < "tests/Dockerfile.$name" >/dev/null \
    || { log "BUILD FAIL: $name"; FAILED+=("$name(build)"); continue; }

  ok()  { log "  OK: $1"; }
  bad() { log "  FAIL: $1"; FAILED+=("$name: $1"); }
  check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
  x() { docker exec "$ctr" bash -c "$*"; }
  # harden STEP ARGS... → runs vpsctl harden, log in /tmp, returns its exit code.
  harden() { local step=$1; shift; x "vpsctl harden $*" > "/tmp/vpsctl-$name-$step.log" 2>&1; }
  # Capture sshd -T before grepping: `| grep -q` kills sshd with SIGPIPE.
  # mkdir: sshd -T needs /run/sshd, which goes away whenever ssh.service stops.
  sshdT() { x "mkdir -p /run/sshd && out=\$(sshd -T ${2:-}) && grep -Eqx '$1' <<< \"\$out\""; }
  listening() { x "test -n \"\$(ss -ltnH 'sport = :$1')\""; }
  login() { x "ssh -i $1 -p $2 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 ${4:-testop}@localhost '${3:-true}'"; }
  fw_allows() {
    case $name in
      rockylinux-*) x "firewall-cmd --list-ports | tr ' ' '\n' | grep -qx '$1/tcp'" \
                      || { [[ $1 == 22 ]] && x 'firewall-cmd --list-services | grep -qw ssh'; } ;;
      *) x "ufw status | grep -qE '^$1/tcp[[:space:]]'" ;;
    esac
  }

  start "$ctr" || { bad "container start"; continue; }

  # Pre-state: socket distros must really be in socket mode.
  case $name in
    ubuntu-24.04|debian-13)
      check "pre-state: ssh.socket enabled" x 'systemctl is-enabled --quiet ssh.socket'
      check "pre-state: ssh.socket active" x 'systemctl is-active --quiet ssh.socket' ;;
  esac

  portarg=${port:+--port $port}
  P=${port:-22}

  # --- Run 1: full hardening -------------------------------------------------
  harden run1 --user testop --yes --key-out /root/k $portarg
  rc=$?
  if [[ $rc != 0 ]]; then
    bad "run 1 exit $rc (see /tmp/vpsctl-$name-run1.log)"; docker rm -f "$ctr" >/dev/null; continue
  fi
  ok "run 1 exit 0"

  check "passwordauthentication no" sshdT 'passwordauthentication no'
  check "kbd-interactive no" sshdT '(kbdinteractiveauthentication|challengeresponseauthentication) no'
  check "permitrootlogin no" sshdT 'permitrootlogin no'
  check "effective port $P" sshdT "port $P"
  check "-C probe pubkey yes" sshdT 'pubkeyauthentication yes' '-C user=testop,host=localhost,addr=127.0.0.1'
  check "listener on $P" listening "$P"
  [[ $P != 22 ]] && check "port 22 closed after port change" eval '! listening 22'
  check "user testop in admin group" x 'groups testop | grep -qE "\b(sudo|wheel)\b"'
  check "key login works" login /root/k "$P"
  check "sudo -n works in user session" login /root/k "$P" 'sudo -n true'
  check "sudoers file present (mode 440)" x 'test "$(stat -c %a /etc/sudoers.d/99-vpsctl-testop)" = 440'
  check "key-out mode 600" x 'test "$(stat -c %a /root/k)" = 600'

  case $name in
    rockylinux-*) check "firewalld active" x 'systemctl is-active --quiet firewalld' ;;
    *) check "ufw active" x 'ufw status | grep -q "Status: active"' ;;
  esac
  check "firewall allows $P" fw_allows "$P"
  [[ $P != 22 ]] && check "firewall no longer allows 22" eval '! fw_allows 22'

  # fail2ban: jail active + a ban materializes in the firewall backend.
  check "fail2ban sshd jail active" x 'fail2ban-client status sshd'
  x 'fail2ban-client set sshd banip 203.0.113.1' >/dev/null 2>&1
  sleep 2
  check "functional ban materialized" x '
    nft list ruleset 2>/dev/null | grep -q 203.0.113.1 && exit 0
    iptables -L -n 2>/dev/null | grep -q 203.0.113.1 && exit 0
    ipset list 2>/dev/null | grep -q 203.0.113.1 && exit 0
    for s in $(firewall-cmd --get-ipsets 2>/dev/null); do
      firewall-cmd --ipset="$s" --get-entries | grep -q 203.0.113.1 && exit 0
    done; exit 1'
  x 'fail2ban-client set sshd unbanip 203.0.113.1' >/dev/null 2>&1

  case $name in
    rockylinux-*) check "dnf-automatic timer" x 'systemctl is-enabled --quiet dnf-automatic.timer' ;;
    *) check "apt-daily-upgrade timer" x 'systemctl is-enabled --quiet apt-daily-upgrade.timer' ;;
  esac
  x 'sysctl -n net.ipv4.tcp_syncookies 2>/dev/null | grep -q 1' \
    && ok "tcp_syncookies=1" || log "  note: tcp_syncookies not applied (container /proc limit)"
  check "Hardening Record names testop" x 'grep -q "\"admin_user\": \"testop\"" /var/lib/vpsctl/hardening.json'
  check "Hardening Record holds no key" x '! grep -q "PRIVATE KEY" /var/lib/vpsctl/hardening.json'

  # --- Idempotency -----------------------------------------------------------
  harden run2 --user testop --yes --key-out /root/k $portarg
  rc=$?; [[ $rc == 0 ]] && ok "run 2 idempotent exit 0" || bad "run 2 exit $rc"
  check "run 2 skipped the gate (already hardened)" grep -q 'already hardened' "/tmp/vpsctl-$name-run2.log"
  harden run3 --user testop --yes
  rc=$?; [[ $rc == 0 ]] && ok "flagless re-run exit 0" || bad "flagless re-run exit $rc"
  check "flagless re-run kept port $P" sshdT "port $P"

  # --- Rotate key ------------------------------------------------------------
  harden rotate --user testop --yes --rotate-key --key-out /root/k2
  rc=$?; [[ $rc == 0 ]] && ok "rotate-key exit 0" || bad "rotate-key exit $rc"
  check "new key logs in" login /root/k2 "$P"
  check "old key rejected" eval '! login /root/k "$P"'

  # --- Forced apply failure: target port already taken -----------------------
  # A second sshd squats on F, so the restart/socket bind on F fails and the
  # run must restore: old port still configured, allowed and listening.
  F=2399
  x "mkdir -p /run/sshd && /usr/sbin/sshd -p $F -o PidFile=/run/blocker.pid" \
    || bad "could not start port blocker on $F"
  harden fail --user testop --yes --port $F
  rc=$?; [[ $rc == 1 ]] && ok "forced apply failure exit 1" || bad "forced apply failure exit $rc (want 1)"
  check "failure: effective port still $P" sshdT "port $P"
  check "failure: still listening on $P" listening "$P"
  check "failure: firewall still allows $P" fw_allows "$P"
  check "failure: firewall rule for $F rolled back" eval "! fw_allows $F"
  check "failure: key login on $P works" login /root/k2 "$P"
  x 'kill $(cat /run/blocker.pid)'

  # --- Port change on a hardened host; foreign 80/tcp rule survives ----------
  case $name in
    rockylinux-*) x 'firewall-cmd --permanent --add-port=80/tcp && firewall-cmd --reload' >/dev/null ;;
    *) x 'ufw allow 80/tcp' >/dev/null
       # Other forms opening the old port: all must be closed by the move.
       check "move: pre-existing ufw limit $P/tcp + allow $P" x "ufw limit $P/tcp && ufw allow $P"
       [[ $P == 22 ]] && check "move: pre-existing ufw OpenSSH profile" x 'ufw allow OpenSSH' ;;
  esac
  N=2200
  harden move --user testop --yes --port $N
  rc=$?; [[ $rc == 0 ]] && ok "port change $P -> $N exit 0" || bad "port change exit $rc"
  check "move: effective port $N" sshdT "port $N"
  check "move: listener on $N" listening "$N"
  check "move: $P closed" eval "! listening $P"
  check "move: firewall allows $N" fw_allows "$N"
  check "move: firewall no longer allows $P" eval "! fw_allows $P"
  [[ $name != rockylinux-* ]] && check "move: no ufw limit/proto-less/OpenSSH rule left for $P" \
    eval "! x \"ufw status | grep -qE '^($P(/tcp)?|OpenSSH)[[:space:]]'\""
  check "move: 80/tcp rule survived" fw_allows 80
  check "move: key login on $N" login /root/k2 "$N"
  check "move: still hardened" sshdT 'passwordauthentication no'

  check "harden logs free of private key" eval '! x "grep -rs \"PRIVATE KEY\" /var/log/vpsctl"'
  check "action log has one line per run" x 'test "$(grep -c " harden " /var/log/vpsctl/actions.log)" = 6'
  docker rm -f "$ctr" >/dev/null 2>&1

  # --- Fresh image without sudo + explicit Port in sshd_config ---------------
  # Bash bug 5: sudoers were written before sudo existed. Also: an explicit
  # `Port 22` in sshd_config (some provider images) must be neutralized.
  ctr=vpsctl-bare-$name-$$
  start "$ctr" || { bad "bare container start"; continue; }
  case $name in
    rockylinux-*) x 'rpm -e --nodeps sudo' >/dev/null 2>&1 ;; # dnf refuses: sudo is a protected package
    *) x 'SUDO_FORCE_REMOVE=yes DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq sudo' >/dev/null 2>&1 ;;
  esac
  check "bare: sudo removed" eval '! x "command -v sudo"'
  x 'printf "\nPort 22\n" >> /etc/ssh/sshd_config'
  D=${port:-5890}
  harden bare --user bareop --yes --key-out /root/kb --port $D
  rc=$?; [[ $rc == 0 ]] && ok "bare run exit 0" || bad "bare run exit $rc (see /tmp/vpsctl-$name-bare.log)"
  check "bare: sudo installed" x 'command -v sudo'
  check "bare: foreign Port commented" x 'grep -q "^# vpsctl: disabled" /etc/ssh/sshd_config'
  check "bare: exactly one port $D" x "mkdir -p /run/sshd && test \"\$(sshd -T | grep -c '^port ')\" = 1"
  check "bare: key login + sudo on $D" login /root/kb "$D" 'sudo -n true' bareop
  docker rm -f "$ctr" >/dev/null 2>&1

  log "=== $name done ==="
done

if [[ ${#FAILED[@]} -gt 0 ]]; then
  printf 'FAILED: %s\n' "${FAILED[@]}"
  exit 1
fi
log "ALL CONTAINER TESTS PASSED"
