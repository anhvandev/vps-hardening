---
phase: 5
title: "Tests + shellcheck + docs"
status: pending
priority: P1
effort: "4h"
dependencies: [4]
---

# Phase 5: Tests + shellcheck + docs

## Overview
Kiểm chứng acceptance bằng container systemd (có **pre-state assertions**) + shellcheck + static guards; viết README (usage, ma trận tested-vs-expected, recovery guide). Quyết định fail2ban journalmatch và EL8 keyword bằng test thật.

## Requirements
- Functional:
  - `tests/test-static.sh`: `bash -n` mọi file; `shellcheck -S warning vps-hardening.sh lib/*.sh tests/*.sh`; grep-guards:
    - không `systemctl reload ssh`/`sshd` trong code
    - không `99-*.conf` làm drop-in sshd chính (00-hardening.conf)
    - không `ss -ltn | grep :` substring (phải `ss -ltnH "sport = :"`)
    - mọi lib source dưới `set -euo pipefail` không tự abort: test bằng `bash -ec 'set -euo pipefail; source lib/detect.sh'` trên môi trường non-socket
  - `tests/test-container.sh`: docker/podman, image systemd-enabled (pin tag/digest; tự build Dockerfile tối thiểu nếu image sẵn không ổn — Dockerfile là source of truth). Ma trận:
    - `ubuntu:22.04` (service), `ubuntu:24.04` (socket), `debian:12` (service), `debian:13` (socket), `rockylinux:9` (wheel + firewalld), **`rockylinux:8`** (kiểm chứng `KbdInteractiveAuthentication` trên OpenSSH 8.0 — nếu fail thì implement feature-probe fallback `ChallengeResponseAuthentication`)
    - **Pre-state assertion bắt buộc per image**: ubuntu:24.04 + debian:13 PHẢI assert `systemctl is-active ssh.socket` trước khi chạy script (nếu image không ở socket mode → force-enable trong Dockerfile: `systemctl disable ssh.service; systemctl enable ssh.socket`; nếu vẫn không → fail test, không âm thầm pass qua service path).
    - Mô phỏng `50-cloud-init.conf` (`PasswordAuthentication yes`) trong container để kiểm chứng precedence 00- vs 50-.
    - Mỗi test: chạy `--user testop --yes --key-out /root/k [--port 2222]` → assert: user + group admin; sshd -T 3 giá trị; sshd -T -C user=testop; `ss -ltnH "sport = :<P>"`; password auth từ chối; firewall chỉ mở P; fail2ban jail active; idempotent run 2; flagless re-run giữ nguyên custom port.
    - **Functional ban test**: `fail2ban-client set sshd banip 203.0.113.1` → verify rule xuất hiện trong nft/iptables/firewalld thật → unban. Nếu ban không materialize trên debian:13/ubuntu:24.04 → thêm journalmatch custom vào jail drop-in (phase 3 risk).
    - **Log safety test**: sau run, `grep -c "PRIVATE KEY" /var/log/vps-hardening-*.log` == 0.
  - Đổi port case riêng: ubuntu:24.04 + debian:13 với `--port 2222` → assert listener 2222, 22 mất sau stage B; assert generator probe path (log ghi nhận generator có/không).
- Non-functional: chạy được trên máy dev linux có docker; skip gracefully khi thiếu docker; dọn container sau test, không orphan; runtime < ~10 phút.

## Docs
- `README.md` (root):
  - Usage: `bash vps-hardening.sh --user NAME [--port N] [--yes --key-out /root/key]`
  - Ma trận **tested** (5-6 image trên) vs **expected-to-work** (Ubuntu 25.x, Debian 11, Fedora, openSUSE, Arch, EL10 — detection cover nhưng chưa test) — trung thực, không quảng cáo quá.
  - Yêu cầu: systemd làm PID 1 (OpenVZ/LXC không hỗ trợ).
  - **SELinux caveat**: restorecon/semanage paths không test được trong container — đã review + verify tay 1 lần trên VM Rocky 9 thật (ghi ngày/kết quả vào đây khi làm), dùng cẩn thận trên SELinux Enforcing.
  - **Recovery guide**: lockout → console web provider → sửa `/etc/ssh/sshd_config.d/00-hardening.conf` → `systemctl restart ssh` (hoặc ssh.socket); nếu port đổi + firewall chặn → console: `ufw allow 22/tcp` / `firewall-cmd --add-service=ssh`.
  - Private key chỉ in 1 lần ra terminal / `--key-out`; `--rotate-key` khi mất key.
  - cloud-init: script ghi `99-hardening.cfg` chặn re-inject key cho default user.
- Không tạo docs/ mở rộng ngoài yêu cầu.

## Related Code Files
- Create: `tests/test-static.sh`, `tests/test-container.sh`, `tests/Dockerfile.*` (hoặc pin image list), `README.md`

## Implementation Steps
1. test-static.sh (nhanh, chạy ngay khi code có).
2. Dockerfile tối thiểu per family (systemd + openssh-server + socket force-enable cho ubuntu:24.04/debian:13).
3. test-container.sh: loop ma trận, pre-state assert, run, assert, functional ban test, log safety grep, teardown sạch.
4. rockylinux:8 quyết định keyword fallback; ban test quyết định journalmatch.
5. README.md với ma trận tested-vs-expected + recovery.
6. `ak plan check` cập nhật phase status.

## Success Criteria
- [x] shellcheck sạch ở level warning (hoặc disable-comment có lý do)
- [x] Static guards pass (không reload ssh, không substring grep ss, libs không tự abort dưới set -e)
- [x] Ma trận pass với pre-state assertions: socket distros thật sự chạy socket path
- [x] Đổi port trên ubuntu:24.04 + debian:13: port mới listen, 22 đóng sau verify
- [x] Functional ban test: IP bị ban thật trong firewall backend
- [x] Log không chứa private key
- [x] Flagless re-run giữ custom port
- [x] Không container orphan (`docker ps` sạch)
- [x] README: ma trận tested-vs-expected + recovery guide + systemd requirement + SELinux caveat

## Risk Assessment
- systemd container ≠ VPS thật (cloud-init drop-in vắng, socket preset khác) → mô phỏng 50-cloud-init.conf + force socket mode trong Dockerfile + pre-state assert; phần còn lại ghi giới hạn README.
- SELinux không enforce trong container → demote khỏi hard acceptance: verify tay 1 lần trên VM thật, ghi kết quả vào README; README ghi caveat rõ.
- Image bên thứ ba mất tag → Dockerfile tự build là source of truth.
- SSH loopback không chạy được trong một số container → fallback assert `sshd -T` + `ss -ltnH` + `su - user -c true`.
- Ubuntu 25.x PerSourcePenalties throttle scripted login test → không có 25.x trong matrix (expected-only), ghi README.
