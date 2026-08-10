---
phase: 1
title: "Core: detection + user + key"
status: pending
priority: P1
effort: "4h"
dependencies: []
---

# Phase 1: Core — detection + user + key

## Overview
Nền tảng của script: `lib/logging.sh`, `lib/detect.sh` (feature-detection distro/daemon/SELinux), `lib/user.sh` (tạo user mới + key ed25519, lock user cloud mặc định). Chưa đụng SSH config.

## Requirements
- Functional:
  - `detect.sh` export: `DISTRO_ID`, `FAMILY` (debian|rhel|suse|arch), `SSH_UNIT` (ssh|sshd), `SOCKET_MODE` (true|false), `SELINUX` (true|false), `ADMIN_GROUP` (sudo|wheel), `PKG` (apt|dnf|zypper|pacman)
  - `user.sh`: `create_admin_user NAME` — adduser (debian) / useradd (khác); `install_user_key NAME` — sinh ed25519 (tạm thời trong file an toàn, umask 077), cài pubkey vào `~/.ssh/authorized_keys` (install -m700/-m600, owner đúng), `restorecon -Rv` nếu SELINUX; in private key đúng 1 lần ra **`/dev/tty`** (KHÔNG stdout — tránh tee/log capture) với cảnh báo lưu ngay
  - `rotate_user_key NAME` — tái sinh + cài lại + in lại key (cho `--rotate-key`; cũng dùng khi run trước chưa qua verify gate thì run sau bắt buộc reprint/rotate thay vì skip âm thầm)
  - `lock_default_users` — candidate list: ubuntu debian rocky almalinux cloud-user centos ec2-user fedora opensuse arch admin; với mỗi user tồn tại (`id -u`): xóa `~user/.ssh/authorized_keys`, `usermod -L`, `usermod -s /usr/sbin/nologin`. KHÔNG userdel. Skip user vừa tạo.
- Non-functional: idempotent (user tồn tại → skip tạo, key đã cài → skip); mọi hàm fail → `die` với message rõ; set -euo pipefail ở orchestrator.

## Architecture
Detection bằng runtime probes, không parse VERSION_ID. **Quan trọng: mọi lib được source dưới `set -euo pipefail` nên TUYỆT ĐỐI không dùng `cmd && VAR=x` hay probe loop trần làm statement cuối — viết `if ...; then ...; fi` hoặc append `|| true`; mọi sourced file phải kết thúc status 0** (phase 5 có static test bắt lỗi này).

Preflight init system TRƯỚC mọi probe systemd: `[[ -d /run/systemd/system ]]` — nếu không phải systemd (OpenVZ/LXC/chroot) → `die "unsupported environment: systemd required"` (ghi rõ giới hạn này trong README scope).

```bash
. /etc/os-release
FAMILY=unknown
case " ${ID_LIKE:-} $ID " in
  *rhel*|*fedora*) FAMILY=rhel;;
  *suse*)          FAMILY=suse;;
  *debian*|*ubuntu*) FAMILY=debian;;
  *arch*)          FAMILY=arch;;
esac
SSH_UNIT=ssh
if [[ $FAMILY =~ ^(rhel|suse|arch)$ || ${ID:-} == fedora ]]; then SSH_UNIT=sshd; fi
SOCKET_MODE=false
for s in ssh.socket sshd.socket; do
  if systemctl list-unit-files "$s" &>/dev/null && \
     { systemctl is-active --quiet "$s" || systemctl is-enabled --quiet "$s"; }; then
    SOCKET_MODE=true
  fi
done
SELINUX=false
if command -v getenforce &>/dev/null && [[ $(getenforce) != Disabled ]]; then SELINUX=true; fi
ADMIN_GROUP=sudo
if [[ $FAMILY != debian ]]; then ADMIN_GROUP=wheel; fi
return 0 2>/dev/null || true
```
SOCKET_MODE check cả `is-enabled` (không chỉ `is-active`) để bắt trạng thái enabled-but-inactive.

**Wheel sudoers (generic, mọi non-debian):** khi `ADMIN_GROUP=wheel` → kiểm tra `%wheel` active trong sudoers (`grep -qE '^[[:space:]]*%wheel' /etc/sudoers /etc/sudoers.d/* 2>/dev/null`); nếu không → ghi `/etc/sudoers.d/90-wheel` (`%wheel ALL=(ALL:ALL) ALL`, chmod 440) rồi `visudo -c` validate. Áp cho rhel/suse/arch — không chỉ Arch.

**cloud-init neutralization (defer-note, implement rẻ):** ghi `/etc/cloud/cloud.cfg.d/99-hardening.cfg` (`disable_root: true`, `users: []`) nếu cloud-init tồn tại — chặn cloud-init tái inject key cho default user sau reboot/datasource refresh.

## Related Code Files
- Create: `lib/logging.sh`, `lib/detect.sh`, `lib/user.sh`

## Implementation Steps
1. `logging.sh`: info/warn/err/die với prefix màu (tắt màu khi không TTY); helper `run_if_missing`.
2. `detect.sh`: probes trên + assert `EUID == 0`, assert `ID` thuộc tập hỗ trợ (warn nếu ngoài).
3. `user.sh`: 3 hàm trên; gen key bằng `ssh-keygen -t ed25519 -f <tmp> -N "" -C "vps-hardening-<host>"`; private key in qua heredoc block rõ ràng, xóa file tạm sau.
4. Guard: nếu NAME trùng root hoặc trùng default-user sẽ lock → die.
5. Unit-ish test tay: chạy detect trên máy local in ra bảng giá trị.

## Success Criteria
- [x] `detect.sh` chạy được, export đủ biến, fail rõ khi không phải root; **die rõ khi không phải systemd**
- [x] **Mọi sourced lib kết thúc status 0 dưới `set -euo pipefail` trên cả debian lẫn non-socket systems** (không tự abort)
- [x] Wheel sudoers được provision trên rhel/suse/arch (không chỉ arch)
- [x] cloud-init drop-in `99-hardening.cfg` được ghi khi cloud-init tồn tại
- [x] Tạo user + key: `id`, `sudo -l -U NAME`, `ssh -i key NAME@localhost` (localhost smoke) OK; key in ra /dev/tty không lọt vào stdout/log
- [x] Lock default user: passwd -S → L, shell nologin
- [x] Chạy lại: skip sạch, exit 0

## Risk Assessment
- Key gen trong /tmp bị đọc: dùng `mktemp -d` chmod 700 + umask 077, shred/rm sau khi cài. Signal bị break: file tạm còn sót → response: trap cleanup EXIT.
- `ubuntu` user trùng tên user mới → die sớm (đã guard).
- Mất private key sau run chưa hoàn tất gate → run sau vẫn skip key → credential không ai giữ: guard bằng `--rotate-key` + force reprint khi gate chưa confirm.
