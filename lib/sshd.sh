#!/usr/bin/env bash
# lib/sshd.sh - two-stage sshd drop-in hardening with lockout-safe apply.
#
# Stage A: Port only. Stage B: auth hardening (applied ONLY after the verify
# gate). Never uses `systemctl reload` (Debian 13 socket bug #1128329).
#
# Requires (from detect.sh): FAMILY SSH_UNIT SOCKET_MODE SSH_SOCKET_UNIT SELINUX PKG

SSH_DROPIN_DIR=/etc/ssh/sshd_config.d
SSH_DROPIN=$SSH_DROPIN_DIR/00-hardening.conf
SSH_SOCKET_DROPIN=/etc/systemd/system/ssh.socket.d/99-hardening-listen.conf

# ---------------------------------------------------------------------------
# Port derivation
# ---------------------------------------------------------------------------

# effective_port [FLAG_PORT] — flag wins; else existing drop-in; else live
# `sshd -T`; else 22. Flagless re-runs therefore never revert a custom port.
effective_port() {
  local flag_port=${1:-} live
  if [[ -n $flag_port ]]; then
    printf '%s\n' "$flag_port"
    return 0
  fi
  if [[ -f $SSH_DROPIN ]]; then
    live=$(awk '/^[[:space:]]*Port[[:space:]]/{print $2; exit}' "$SSH_DROPIN")
    if [[ -n $live ]]; then
      printf '%s\n' "$live"
      return 0
    fi
  fi
  ensure_hostkeys
  live=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}') || true
  printf '%s\n' "${live:-22}"
}

# ensure_hostkeys — sshd -T/-t need host keys and the privilege-separation
# directory (/run/sshd is normally created by the daemon's tmpfiles on boot;
# validating before first start can hit its absence).
ensure_hostkeys() {
  if ! compgen -G '/etc/ssh/ssh_host_*' >/dev/null; then
    ssh-keygen -A >/dev/null 2>&1 || die "ssh-keygen -A failed (no host keys)"
  fi
  if [[ ! -d /run/sshd ]]; then
    install -d -m 755 /run/sshd
  fi
}

# ---------------------------------------------------------------------------
# Snapshot / rollback (drop-in + socket drop-in; firewall handled by caller)
# ---------------------------------------------------------------------------

# snapshot_state SNAP_DIR — capture pre-mutation SSH state (drop-ins, old
# port, and the firewall's SSH-relevant allow rules for rollback).
snapshot_state() {
  local snap=$1
  mkdir -p "$snap"
  if [[ -f $SSH_DROPIN ]]; then
    cp -a "$SSH_DROPIN" "$snap/dropin"
  else
    : > "$snap/no-dropin"
  fi
  if [[ -f $SSH_SOCKET_DROPIN ]]; then
    cp -a "$SSH_SOCKET_DROPIN" "$snap/socket-dropin"
  fi
  effective_port > "$snap/old-port"
  if command -v ufw &>/dev/null; then
    ufw status 2>/dev/null > "$snap/ufw-status" || true
  fi
  if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
    firewall-cmd --list-all 2>/dev/null > "$snap/firewalld-all" || true
  fi
  info "snapshot saved (old effective port: $(cat "$snap/old-port"))"
}

# rollback_state SNAP_DIR — restore snapshot; never dies (best effort).
rollback_state() {
  local snap=$1
  warn "rolling back SSH state to pre-run snapshot"
  if [[ -f $snap/dropin ]]; then
    cp -a "$snap/dropin" "$SSH_DROPIN" || warn "failed to restore drop-in"
  elif [[ -f $snap/no-dropin ]]; then
    rm -f "$SSH_DROPIN" || true
  fi
  if [[ -f $snap/socket-dropin ]]; then
    cp -a "$snap/socket-dropin" "$SSH_SOCKET_DROPIN" || true
  else
    rm -f "$SSH_SOCKET_DROPIN" || true
  fi
  systemctl daemon-reload 2>/dev/null || true
  if [[ $SOCKET_MODE == true ]]; then
    systemctl restart "$SSH_SOCKET_UNIT" 2>/dev/null \
      || systemctl restart "$SSH_UNIT" 2>/dev/null \
      || warn "daemon restart during rollback failed"
  else
    systemctl restart "$SSH_UNIT" 2>/dev/null \
      || service "$SSH_UNIT" restart 2>/dev/null \
      || warn "daemon restart during rollback failed"
  fi
  # Firewall: remove any allow rule for a port that was NOT open pre-run
  # (e.g. the new port opened by firewall_open_ssh before a failed apply).
  local old_port p
  old_port=$(cat "$snap/old-port" 2>/dev/null || true)
  if command -v ufw &>/dev/null && [[ -f $snap/ufw-status ]]; then
    while read -r p; do
      [[ -n $p && $p != "$old_port" ]] && ! grep -q "^${p}/tcp" "$snap/ufw-status" \
        && ufw delete allow "$p/tcp" >/dev/null 2>&1 || true
    done < <(ufw status 2>/dev/null \
             | awk '/ALLOW/ {sub(/ \(v6\)$/,"",$1); print $1}' \
             | awk -F/ '$2=="tcp" {print $1}' | grep -E '^[0-9]+$' || true)
  elif command -v firewall-cmd &>/dev/null && [[ -f $snap/firewalld-all ]]; then
    while read -r p; do
      [[ -n $p && $p != "$old_port" ]] && ! grep -q "${p}/tcp" "$snap/firewalld-all" \
        && firewall-cmd --permanent --remove-port="$p/tcp" >/dev/null 2>&1 || true
    done < <(firewall-cmd --list-all 2>/dev/null | tr ' ' '\n' \
             | grep -E '^[0-9]+/tcp$' | cut -d/ -f1 || true)
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
}

# ---------------------------------------------------------------------------
# Drop-in writer (deterministic, idempotent)
# ---------------------------------------------------------------------------

# _kbd_keyword — KbdInteractiveAuthentication (OpenSSH >= 8.2) or the EL8
# fallback ChallengeResponseAuthentication, probed from the live daemon.
_kbd_keyword() {
  if sshd -T 2>/dev/null | grep -qi '^kbdinteractiveauthentication '; then
    printf 'KbdInteractiveAuthentication\n'
  else
    printf 'ChallengeResponseAuthentication\n'
  fi
}

# write_dropin STAGE PORT — STAGE=A writes Port only; STAGE=B adds auth
# hardening. Returns 1 when content is unchanged (caller may skip apply).
write_dropin() {
  local stage=$1 port=$2 tmp kbd
  install -d -m 755 "$SSH_DROPIN_DIR"
  tmp=$(mktemp) || die "mktemp failed"
  chmod 644 "$tmp"
  {
    printf '# Managed by vps-hardening.sh — do not edit by hand.\n'
    printf 'Port %s\n' "$port"
    if [[ $stage == B ]]; then
      kbd=$(_kbd_keyword)
      printf 'PasswordAuthentication no\n'
      printf '%s no\n' "$kbd"
      printf 'PubkeyAuthentication yes\n'
      printf 'PermitRootLogin no\n'
    fi
  } > "$tmp"
  if [[ -f $SSH_DROPIN ]] && cmp -s "$tmp" "$SSH_DROPIN"; then
    rm -f "$tmp"
    return 1
  fi
  # `cat >` instead of `mv`: mv-over-existing returns non-zero on some
  # coreutils (observed on EL8), which callers read as "no change".
  cat "$tmp" > "$SSH_DROPIN" || { rm -f "$tmp"; die "failed to write $SSH_DROPIN"; }
  rm -f "$tmp"
  info "wrote $SSH_DROPIN (stage $stage, port $port)"
  return 0
}

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

# assert_include_directive — drop-ins only count when sshd_config includes them.
assert_include_directive() {
  local cfg=/etc/ssh/sshd_config
  [[ -f $cfg ]] || die "$cfg not found — is openssh-server installed?"
  if grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$cfg"; then
    return 0
  fi
  warn "Include directive missing in $cfg — prepending"
  local tmp
  tmp=$(mktemp) || die "mktemp failed"
  { printf 'Include /etc/ssh/sshd_config.d/*.conf\n'; cat "$cfg"; } > "$tmp"
  cat "$tmp" > "$cfg"
  rm -f "$tmp"
}

# scan_match_blocks — warn loudly about Match blocks (can re-enable password
# auth per-connection, overriding our global drop-in).
scan_match_blocks() {
  local hits
  hits=$(grep -n '^[[:space:]]*Match' /etc/ssh/sshd_config "$SSH_DROPIN_DIR"/*.conf 2>/dev/null) || true
  if [[ -n $hits ]]; then
    warn "Match blocks found — they can override global auth settings:"
    printf '%s\n' "$hits" >&2
  fi
  local f
  for f in "$SSH_DROPIN_DIR"/*.conf; do
    [[ -f $f && $f != "$SSH_DROPIN" ]] && warn "foreign drop-in present: $f"
  done
  # Hard rule: never let a false `&&` compound be this function's exit status.
  return 0
}

# validate_sshd PORT CHECK_AUTH(0|1) USER — sshd -t + sshd -T (+ -C probe).
validate_sshd() {
  local port=$1 check_auth=$2 user=$3 out
  ensure_hostkeys
  sshd -t || die "sshd -t failed — refusing to apply invalid config"
  out=$(sshd -T 2>/dev/null) || die "sshd -T failed"
  if ! grep -qx "port $port" <<< "$out"; then
    die "sshd -T: expected 'port $port', got: $(grep '^port ' <<< "$out")"
  fi
  # Multiple Port directives are legal — but then we cannot guarantee which
  # the operator expects, and our firewall management only tracks one.
  if [[ $(grep -c '^port ' <<< "$out") -gt 1 ]]; then
    die "sshd -T reports multiple Port directives — refusing to manage"
  fi
  if [[ $check_auth == 1 ]]; then
    _assert_auth_values "$out"
    # -C probe catches Match-block divergence for our specific user.
    out=$(sshd -T -C "user=$user,host=localhost,addr=127.0.0.1" 2>/dev/null) \
      || die "sshd -T -C failed"
    _assert_auth_values "$out"
  fi
  scan_match_blocks
  info "sshd config validated (port $port, auth-check=$check_auth)"
}

# _assert_auth_values OUT — die unless the hardened values are effective.
_assert_auth_values() {
  local out=$1
  grep -qx 'passwordauthentication no' <<< "$out" \
    || die "effective config still allows password auth"
  grep -Eqx '(kbdinteractiveauthentication|challengeresponseauthentication) no' <<< "$out" \
    || die "effective config still allows keyboard-interactive auth"
  grep -qx 'permitrootlogin no' <<< "$out" \
    || die "effective config still permits root login"
  grep -qx 'pubkeyauthentication yes' <<< "$out" \
    || die "effective config does not have pubkeyauthentication yes"
}

# ---------------------------------------------------------------------------
# Apply (never `reload` — Debian 13 socket bug #1128329)
# ---------------------------------------------------------------------------

# selinux_allow_ssh_port PORT — teach ssh_port_t about a custom port.
selinux_allow_ssh_port() {
  local port=$1
  [[ $SELINUX == true ]] || return 0
  if ! command -v semanage &>/dev/null; then
    if [[ $PKG == dnf ]]; then
      info "installing policycoreutils-python-utils for semanage"
      dnf install -y policycoreutils-python-utils \
        || warn "could not install semanage — custom port may fail on SELinux"
    fi
  fi
  if command -v semanage &>/dev/null; then
    if semanage port -l 2>/dev/null | grep -qE "^ssh_port_t\s+tcp\s+.*\b${port}\b"; then
      info "SELinux already allows ssh port $port"
    else
      semanage port -a -t ssh_port_t -p tcp "$port" 2>/dev/null \
        || semanage port -m -t ssh_port_t -p tcp "$port" \
        || warn "semanage failed for port $port — sshd may not bind it"
    fi
  fi
}

# apply_sshd PORT_CHANGED(0|1) PORT — apply per daemon model, then verify the
# listener. Caller must roll back on non-zero return.
apply_sshd() {
  local port_changed=$1 port=$2
  if [[ $port_changed == 1 ]]; then
    selinux_allow_ssh_port "$port"
  fi
  if [[ $SOCKET_MODE == true ]]; then
    systemctl daemon-reload || die "daemon-reload failed"
    if [[ $port_changed == 1 ]]; then
      # Generator probe: Ubuntu 24.04+ ships sshd-socket-generator; Debian 13
      # support is unverified, so probe at runtime and fall back to a manual
      # socket drop-in.
      if ! systemctl cat "$SSH_SOCKET_UNIT" 2>/dev/null \
           | grep -qE "^ListenStream=.*:${port}\b|^ListenStream=${port}\b"; then
        warn "socket generator did not emit port $port — writing manual socket drop-in"
        install -d -m 755 /etc/systemd/system/ssh.socket.d
        printf '[Socket]\nListenStream=\nListenStream=%s\n' "$port" > "$SSH_SOCKET_DROPIN"
        systemctl daemon-reload || die "daemon-reload failed"
      fi
      systemctl restart "$SSH_SOCKET_UNIT" || die "restart $SSH_SOCKET_UNIT failed"
    else
      systemctl restart "$SSH_UNIT" || die "restart $SSH_UNIT failed"
    fi
  else
    systemctl restart "$SSH_UNIT" 2>/dev/null \
      || service "$SSH_UNIT" restart \
      || die "failed to restart $SSH_UNIT"
  fi
  verify_listener "$port"
}

# verify_listener PORT — field-exact check (substring `grep :22` also matches
# :2222; the ss filter does not). Retries 3 times.
verify_listener() {
  local port=$1 _try
  for _try in 1 2 3; do
    if [[ -n $(ss -ltnH "sport = :$port" 2>/dev/null) ]]; then
      info "listener confirmed on port $port"
      return 0
    fi
    sleep 1
  done
  err "no listener on port $port after 3 attempts"
  return 1
}

# assert_port_closed PORT — after stage B, the old port must be gone.
assert_port_closed() {
  local port=$1
  if [[ -n $(ss -ltnH "sport = :$port" 2>/dev/null) ]]; then
    err "old port $port is still listening"
    return 1
  fi
  info "old port $port is closed"
}
