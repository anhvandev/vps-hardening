#!/usr/bin/env bash
# vps-hardening.sh - multi-distro VPS initial hardening orchestrator.
#
# Lock-safe flow: two-stage SSH drop-in (port first, auth hardening ONLY after
# the verify gate), firewall open/close split, snapshot-rollback on failure.
# Modules live in lib/ and never call each other's flow — ordering is decided
# here only.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
STATE_DIR=/var/lib/vps-hardening

usage() {
  cat <<'EOF'
Usage: vps-hardening.sh --user NAME [options]

Required:
  --user NAME       New admin user to create (sudo/wheel + SSH key)

Options:
  --port N          Move SSH to port N (default: keep current effective port)
  --yes             Skip confirmations (automation). Pre-lock assertions still run.
  --key-out PATH    Write the private key to PATH (chmod 600) instead of printing
  --rotate-key      Regenerate + reinstall + reprint the user's SSH key
  --skip-firewall   Do not manage ufw/firewalld
  --skip-fail2ban   Do not install/configure fail2ban
  --skip-updates    Do not configure automatic security updates
  --skip-sysctl     Do not apply sysctl hardening
  -h, --help        Show this help
EOF
}

# ---- flags ----------------------------------------------------------------
USER_NAME='' FLAG_PORT='' ASSUME_YES=0 KEY_OUT='' ROTATE_KEY=0
SKIP_FIREWALL=0 SKIP_FAIL2BAN=0 SKIP_UPDATES=0 SKIP_SYSCTL=0
while [[ $# -gt 0 ]]; do
  case $1 in
    --user)          USER_NAME=${2:?--user needs a value}; shift 2 ;;
    --port)          FLAG_PORT=${2:?--port needs a value}; shift 2 ;;
    --yes)           ASSUME_YES=1; shift ;;
    --key-out)       KEY_OUT=${2:?--key-out needs a value}; shift 2 ;;
    --rotate-key)    ROTATE_KEY=1; shift ;;
    --skip-firewall) SKIP_FIREWALL=1; shift ;;
    --skip-fail2ban) SKIP_FAIL2BAN=1; shift ;;
    --skip-updates)  SKIP_UPDATES=1; shift ;;
    --skip-sysctl)   SKIP_SYSCTL=1; shift ;;
    -h|--help)       usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done
if [[ -z $USER_NAME ]]; then
  echo "ERROR: --user NAME is required" >&2
  usage
  exit 2
fi
if [[ -n $FLAG_PORT && ! $FLAG_PORT =~ ^[0-9]+$ ]] || \
   [[ -n $FLAG_PORT && ( $FLAG_PORT -lt 1 || $FLAG_PORT -gt 65535 ) ]]; then
  echo "ERROR: --port must be 1-65535" >&2
  exit 2
fi
if [[ -n $FLAG_PORT && $SKIP_FIREWALL == 1 ]]; then
  echo "ERROR: --skip-firewall cannot be combined with --port" >&2
  echo "  (the firewall would keep blocking the new SSH port → lockout)" >&2
  exit 2
fi

# ---- preflight: logging + detection (dies on non-root / non-systemd) ------
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/logging.sh"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/detect.sh"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/user.sh"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/sshd.sh"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/firewall.sh"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/services.sh"

mkdir -p "$STATE_DIR"
SNAP_DIR=$(mktemp -d "$STATE_DIR/snap.XXXXXX")
trap 'rm -rf "$SNAP_DIR"' EXIT

umask 077
LOG_FILE=/var/log/vps-hardening-$(date +%Y%m%d-%H%M%S).log
exec > >(tee -a "$LOG_FILE") 2>&1
info "logging to $LOG_FILE"

cat <<EOF
== detection ==
  distro   : $DISTRO_ID (family: $FAMILY)
  ssh unit : $SSH_UNIT (socket activation: $SOCKET_MODE)
  selinux  : $SELINUX
  admin grp: $ADMIN_GROUP
  pkg mgr  : $PKG
EOF

# sudo is stock on debian/rhel images but can be absent in minimal suse/arch.
ensure_sudo() {
  if ! command -v sudo &>/dev/null; then
    warn "sudo not installed — installing"
    case $PKG in
      apt)    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo ;;
      dnf)    dnf install -y sudo ;;
      zypper) zypper --non-interactive install sudo ;;
      pacman) pacman -Sy --noconfirm sudo ;;
      *)      die "cannot install sudo (PKG=$PKG)" ;;
    esac || die "failed to install sudo"
  fi
}

# ---- pre-lock machine assertions (run on BOTH --yes and manual paths) -----
pre_lock_assertions() {
  local name=$1 home authkeys out
  ensure_sudo
  home=$(getent passwd "$name" | cut -d: -f6)
  authkeys="$home/.ssh/authorized_keys"
  # Capture first: piping `sshd -T | grep -q` makes sshd die of SIGPIPE
  # (grep -q exits early) and pipefail turns that into a false failure.
  out=$(sshd -T -C "user=$name,host=localhost,addr=127.0.0.1" 2>/dev/null) \
    || die "pre-lock assertion failed: sshd -T -C errored for $name"
  grep -qx 'pubkeyauthentication yes' <<< "$out" \
    || die "pre-lock assertion failed: pubkey auth not effective for $name"
  [[ -s $authkeys ]] || die "pre-lock assertion failed: $authkeys missing/empty"
  [[ $(stat -c '%a %U' "$authkeys") == "600 $name" ]] \
    || die "pre-lock assertion failed: bad perms on $authkeys"
  sudo -l -U "$name" 2>/dev/null | grep -q 'ALL' \
    || die "pre-lock assertion failed: $name has no sudo privileges"
  su - "$name" -c true \
    || die "pre-lock assertion failed: cannot su to $name"
  info "pre-lock assertions passed for '$name'"
}

# ---- flow -----------------------------------------------------------------
snapshot_state "$SNAP_DIR"
OLD_PORT=$(cat "$SNAP_DIR/old-port")
EFFECTIVE_PORT=$(effective_port "$FLAG_PORT")
PORT_CHANGED=0
if [[ $EFFECTIVE_PORT != "$OLD_PORT" ]]; then
  PORT_CHANGED=1
fi
# Stage B already live + no port change = hardened re-run: skip stage A write
# (would downgrade the drop-in), skip the verify gate, skip restarts.
STAGE_B_LIVE=0
if [[ -f $SSH_DROPIN ]] && grep -q '^PasswordAuthentication no' "$SSH_DROPIN"; then
  STAGE_B_LIVE=1
fi
SKIP_GATE=0
if [[ $STAGE_B_LIVE == 1 && $PORT_CHANGED == 0 ]]; then
  SKIP_GATE=1
fi
info "effective SSH port: $EFFECTIVE_PORT (was: $OLD_PORT)"

create_admin_user "$USER_NAME"

# Credential-gap guard: a key installed by a previous run whose material was
# never emitted means nobody provably holds it — refuse to silently continue.
KEY_MARKER=$STATE_DIR/key-emitted-$USER_NAME
if [[ $ROTATE_KEY == 1 ]]; then
  rotate_user_key "$USER_NAME" "$KEY_OUT"
  : > "$KEY_MARKER"; chmod 600 "$KEY_MARKER"
elif user_key_installed "$USER_NAME"; then
  if [[ ! -f $KEY_MARKER ]]; then
    die "key for '$USER_NAME' exists but was never emitted by this script; re-run with --rotate-key (or delete the key) to continue"
  fi
  info "key already installed for '$USER_NAME' — skipping"
else
  install_user_key "$USER_NAME" "$KEY_OUT"
  : > "$KEY_MARKER"; chmod 600 "$KEY_MARKER"
fi
if [[ $ASSUME_YES == 0 && -z $KEY_OUT ]]; then
  ask_yesno "Have you saved the private key?" n \
    || die "aborting — re-run when the key is saved"
fi

if [[ $SKIP_FIREWALL == 0 ]]; then
  firewall_setup "$EFFECTIVE_PORT"
else
  warn "--skip-firewall: firewall not managed"
fi

assert_include_directive
neutralize_foreign_ports
A_CHANGED=0
if [[ $SKIP_GATE == 0 ]]; then
  if write_dropin A "$EFFECTIVE_PORT"; then
    A_CHANGED=1
  fi
fi
validate_sshd "$EFFECTIVE_PORT" "$STAGE_B_LIVE" "$USER_NAME"

if [[ $PORT_CHANGED == 1 && $SKIP_FIREWALL == 0 ]]; then
  firewall_open_ssh "$EFFECTIVE_PORT"
fi

if [[ $A_CHANGED == 1 || $PORT_CHANGED == 1 ]]; then
  if ! apply_sshd "$PORT_CHANGED" "$EFFECTIVE_PORT"; then
    rollback_state "$SNAP_DIR"
    die "failed to bring up sshd on port $EFFECTIVE_PORT — rolled back"
  fi
fi

# ---- verify gate -----------------------------------------------------------
cat <<EOF

== VERIFY GATE ==
From your local machine, in a NEW terminal (keep this session open!):
  ssh -i <saved-key> -p $EFFECTIVE_PORT $USER_NAME@<this-host>
Then confirm sudo works:  sudo true
EOF
if [[ $SKIP_GATE == 1 ]]; then
  info "stage B already applied and port unchanged — skipping verify gate"
elif [[ $ASSUME_YES == 0 ]]; then
  if [[ ! -r /dev/tty ]]; then
    die "no TTY for the verify gate — re-run with --yes (automation) once safe"
  fi
  if ! ask_yesno "Did the NEW login work?" n; then
    warn "stopping safely: password auth still enabled, default users NOT locked"
    warn "resume later with: $0 --user $USER_NAME${FLAG_PORT:+ --port $FLAG_PORT}"
    exit 3
  fi
else
  warn "--yes: skipping human verify gate (machine assertions still run)"
fi

pre_lock_assertions "$USER_NAME"

B_CHANGED=0
if write_dropin B "$EFFECTIVE_PORT"; then
  B_CHANGED=1
fi
validate_sshd "$EFFECTIVE_PORT" 1 "$USER_NAME"
if [[ $B_CHANGED == 1 || $PORT_CHANGED == 1 ]]; then
  if ! apply_sshd "$PORT_CHANGED" "$EFFECTIVE_PORT"; then
    rollback_state "$SNAP_DIR"
    die "stage B apply failed — rolled back"
  fi
fi

if [[ $PORT_CHANGED == 1 ]]; then
  assert_port_closed "$OLD_PORT" \
    || warn "old port $OLD_PORT still listening — check for foreign Port directives"
  if [[ $SKIP_FIREWALL == 0 ]]; then
    firewall_close_old_ssh "$OLD_PORT" "$EFFECTIVE_PORT"
  fi
fi

lock_default_users "$USER_NAME"
neutralize_cloud_init

[[ $SKIP_FAIL2BAN == 0 ]] && setup_fail2ban "$EFFECTIVE_PORT" || true
[[ $SKIP_UPDATES == 0 ]] && setup_auto_updates || true
[[ $SKIP_SYSCTL == 0 ]] && setup_sysctl || true

cat <<EOF

== SUMMARY ==
  admin user : $USER_NAME (group: $ADMIN_GROUP, key-only SSH)
  ssh port   : $EFFECTIVE_PORT
  password authentication : disabled
  root login : disabled
  default cloud users     : locked
  log        : $LOG_FILE
The private key was shown once / written to ${KEY_OUT:-your terminal}.
Lost it? Re-run with --rotate-key.
Recovery guide: see README.md
EOF
info "done."
