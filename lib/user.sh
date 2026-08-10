#!/usr/bin/env bash
# lib/user.sh - admin user creation, SSH key install/rotation, default cloud
# user lockdown, wheel sudoers provisioning, cloud-init neutralization.
#
# Private key discipline: the private key is printed ONCE to /dev/tty or
# written to the --key-out path. It never crosses fd 1/2, so tee'd logs and
# captured stdout can never contain it.

# Default cloud users to lock. The newly created admin user is skipped.
DEFAULT_CLOUD_USERS=(
  ubuntu debian rocky almalinux cloud-user centos ec2-user fedora opensuse arch admin
)

# guard_user_name NAME — refuse names that collide with root or lock targets.
guard_user_name() {
  local name=$1 u
  [[ $name == root ]] && die "refusing to use 'root' as the admin user name"
  for u in "${DEFAULT_CLOUD_USERS[@]}"; do
    if [[ $name == "$u" ]]; then
      die "refusing name '$name': it is a default cloud user that will be locked"
    fi
  done
  if ! [[ $name =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
    die "invalid user name '$name'"
  fi
}

# provision_wheel_sudoers — generic %wheel sudoers for non-debian families
# (rhel/suse/arch) when no active %wheel rule exists.
provision_wheel_sudoers() {
  [[ $ADMIN_GROUP == wheel ]] || return 0
  if grep -qsE '^[[:space:]]*%wheel' /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    info "wheel sudoers rule already present"
    return 0
  fi
  info "provisioning /etc/sudoers.d/90-wheel"
  printf '%%wheel ALL=(ALL:ALL) ALL\n' > /etc/sudoers.d/90-wheel
  chmod 440 /etc/sudoers.d/90-wheel
  if command -v visudo &>/dev/null; then
    visudo -c &>/dev/null || die "visudo -c failed after writing 90-wheel"
  fi
}

# create_admin_user NAME — idempotent; adduser on debian, useradd elsewhere.
create_admin_user() {
  local name=$1
  guard_user_name "$name"
  if id -u "$name" &>/dev/null; then
    info "user '$name' already exists — skipping creation"
  else
    info "creating user '$name' (admin group: $ADMIN_GROUP)"
    if [[ $FAMILY == debian ]]; then
      adduser --disabled-password --gecos '' "$name" || die "adduser failed"
    else
      useradd -m -s /bin/bash "$name" || die "useradd failed"
    fi
  fi
  usermod -aG "$ADMIN_GROUP" "$name" || die "failed to add '$name' to $ADMIN_GROUP"
  provision_wheel_sudoers
}

# _install_pubkey NAME PUBKEY_FILE — idempotent authorized_keys install.
_install_pubkey() {
  local name=$1 pubkey_file=$2 home ssh_dir authkeys
  home=$(getent passwd "$name" | cut -d: -f6)
  [[ -n $home && -d $home ]] || die "no home directory for '$name'"
  ssh_dir="$home/.ssh"
  authkeys="$ssh_dir/authorized_keys"
  install -d -m 700 -o "$name" -g "$name" "$ssh_dir"
  install -m 600 -o "$name" -g "$name" "$pubkey_file" "$authkeys"
  # SELinux: .ssh created in a non-standard context would silently break key auth.
  if [[ $SELINUX == true ]] && command -v restorecon &>/dev/null; then
    restorecon -Rv "$ssh_dir" &>/dev/null || warn "restorecon on $ssh_dir failed"
  fi
}

# _emit_private_key NAME PRIVKEY_FILE KEY_OUT
# Print once to /dev/tty, or write to KEY_OUT (chmod 600). Never to stdout.
_emit_private_key() {
  local name=$1 privkey_file=$2 key_out=$3
  if [[ -n $key_out ]]; then
    install -m 600 /dev/null "$key_out"
    cat "$privkey_file" > "$key_out"
    chmod 600 "$key_out"
    info "private key written to $key_out (mode 600) — move it to your local machine now"
  else
    if [[ ! -w /dev/tty ]]; then
      die "no TTY available to display the private key; re-run with --key-out PATH"
    fi
    {
      printf '\n================ PRIVATE KEY (shown ONCE) ================\n'
      printf 'User: %s — save this to your local machine NOW, it will not be shown again.\n\n' "$name"
      cat "$privkey_file"
      printf '\n==========================================================\n'
    } > /dev/tty
  fi
}

# _gen_and_install_key NAME KEY_OUT — generate ed25519 pair in a safe tmpdir,
# install pubkey, emit private key, clean up via caller's trap.
_gen_and_install_key() {
  local name=$1 key_out=${2:-} tmpdir
  tmpdir=$(mktemp -d) || die "mktemp failed"
  chmod 700 "$tmpdir"
  (
    umask 077
    ssh-keygen -t ed25519 -f "$tmpdir/key" -N "" \
      -C "vps-hardening-$(hostname -s 2>/dev/null || hostname)" >/dev/null
  ) || { rm -rf "$tmpdir"; die "ssh-keygen failed"; }
  _install_pubkey "$name" "$tmpdir/key.pub"
  _emit_private_key "$name" "$tmpdir/key" "$key_out"
  rm -rf "$tmpdir"
  info "public key installed for '$name'"
}

# user_key_installed NAME — 0 when a non-empty authorized_keys exists.
user_key_installed() {
  local name=$1 home
  home=$(getent passwd "$name" | cut -d: -f6)
  [[ -n $home && -s $home/.ssh/authorized_keys ]]
}

# install_user_key NAME [KEY_OUT] — idempotent install.
install_user_key() {
  local name=$1 key_out=${2:-}
  if user_key_installed "$name"; then
    info "key already installed for '$name' — skipping"
    return 0
  fi
  _gen_and_install_key "$name" "$key_out"
}

# rotate_user_key NAME [KEY_OUT] — always regenerate, reinstall, reprint.
rotate_user_key() {
  local name=$1 key_out=${2:-}
  id -u "$name" &>/dev/null || die "user '$name' does not exist"
  info "rotating SSH key for '$name'"
  _gen_and_install_key "$name" "$key_out"
}

# lock_default_users — lock every present candidate cloud user (never userdel).
lock_default_users() {
  local skip=${1:-} u home
  for u in "${DEFAULT_CLOUD_USERS[@]}"; do
    [[ $u == "$skip" ]] && continue
    id -u "$u" &>/dev/null || continue
    info "locking default cloud user '$u'"
    home=$(getent passwd "$u" | cut -d: -f6)
    if [[ -n $home && -f $home/.ssh/authorized_keys ]]; then
      : > "$home/.ssh/authorized_keys"
    fi
    usermod -L "$u" || warn "usermod -L $u failed"
    usermod -s /usr/sbin/nologin "$u" 2>/dev/null \
      || usermod -s /sbin/nologin "$u" \
      || warn "failed to set nologin shell for $u"
  done
}

# neutralize_cloud_init — stop cloud-init from resurrecting default-user keys.
neutralize_cloud_init() {
  [[ -d /etc/cloud/cloud.cfg.d ]] || return 0
  local f=/etc/cloud/cloud.cfg.d/99-hardening.cfg
  if [[ -f $f ]]; then
    info "cloud-init drop-in already present"
    return 0
  fi
  info "writing $f (block default-user key re-injection)"
  printf 'disable_root: true\nusers: []\n' > "$f"
  chmod 644 "$f"
}
