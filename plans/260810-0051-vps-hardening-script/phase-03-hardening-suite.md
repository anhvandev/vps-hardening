---
phase: 3
title: "Firewall + fail2ban + auto-updates + sysctl"
status: pending
priority: P2
effort: "4h"
dependencies: [1]
---

# Phase 3: Hardening suite

## Overview
`lib/firewall.sh` (ufw / firewalld — **split open/close**), `lib/services.sh` (fail2ban với banaction đúng + auto security updates + sysctl drop-in). Mỗi thành phần cô lập lỗi: fail → warn + tiếp tục (trừ firewall khi đổi port — đường critical).

## Requirements
- Functional:
  - **firewall.sh — 3 hàm tách bạch:**
    - `firewall_setup SSH_PORT` — **gọi VÔ ĐIỀU KIỆN** (cả khi không đổi port): cài + enable firewall, allow SSH port.
      - FAMILY=debian → `apt install -y ufw`, `ufw allow <P>/tcp`, `ufw --force enable` (idempotent: check `ufw status` trước).
      - FAMILY=rhel/suse → firewalld: cài nếu thiếu (`dnf install -y firewalld` / **`zypper install -y firewalld`**), `systemctl enable --now firewalld`, `firewall-cmd --permanent --add-port=<P>/tcp --reload`.
      - FAMILY=arch → warn "no firewall managed", skip.
    - `firewall_open_ssh NEW_PORT` — chỉ khi đổi port, gọi TRƯỚC apply_sshd: allow thêm port mới (ufw `allow`, firewalld `--add-port`). KHÔNG đóng gì ở bước này.
    - `firewall_close_old_ssh NEW_PORT` — chỉ gọi SAU verify_listener thành công: ufw → `ufw delete allow 22/tcp` + delete mọi rule SSH cũ khác NEW_PORT (đọc port cũ từ drop-in trước khi ghi đè); firewalld → `--remove-service=ssh` + `--remove-port=<old>/tcp` (permanent) + reload.
  - **services.sh**
    - `setup_fail2ban`: debian → apt install fail2ban; rhel → `dnf install -y epel-release && dnf install -y fail2ban`; suse → zypper; arch → pacman. Drop-in `/etc/fail2ban/jail.d/00-hardening.local`:
      ```
      [sshd]
      enabled = true
      port = <EFFECTIVE_PORT>
      backend = systemd            # khi FAMILY != debian
      banaction = firewallcmd-ipset   # khi firewalld active
      banaction = nftables-multiport  # debian/ubuntu (nft backend mặc định 24.04+)
      ```
      (banaction theo family; journalmatch mở rộng nếu sshd filter không bắt được `sshd-session`/`ssh@.service` — kiểm chứng bằng functional ban test ở phase 5). `systemctl enable --now fail2ban`, verify `fail2ban-client status sshd`.
    - `setup_auto_updates`: debian → `apt install -y unattended-upgrades` + ghi `/etc/apt/apt.conf.d/20auto-upgrades` deterministic (idempotent); rhel → `dnf install -y dnf-automatic`, sed `apply_updates = yes` trong `/etc/dnf/automatic.conf`, `systemctl enable --now dnf-automatic.timer`; suse/arch → warn skip.
    - `setup_sysctl`: `/etc/sysctl.d/90-hardening.conf`:
      ```
      net.ipv4.conf.all.accept_redirects = 0
      net.ipv4.conf.all.send_redirects = 0
      net.ipv4.conf.default.accept_source_route = 0
      net.ipv4.tcp_syncookies = 1
      net.ipv6.conf.all.accept_redirects = 0
      kernel.kptr_restrict = 2
      ```
      `sysctl --system || warn` (không die — container có thể thiếu quyền).
- Non-functional: mỗi hàm trả 0/1 rõ; lỗi fail2ban/auto-update/sysctl chỉ warn (không làm hỏng SSH đã cấu hình).

## Architecture
Orchestrator (phase 4) gọi theo thứ tự: `firewall_setup` (sớm, vô điều kiện) → [`firewall_open_ssh` nếu đổi port] → apply sshd stage A → verify → [`firewall_close_old_ssh` sau verify] → fail2ban → auto-updates → sysctl.

## Related Code Files
- Create: `lib/firewall.sh`, `lib/services.sh`

## Implementation Steps
1. firewall.sh: 3 hàm setup/open/close, 2 nhánh ufw/firewalld + skip path.
2. fail2ban: install per PKG, jail drop-in với banaction per family, verify jail status.
3. auto-updates: 20auto-upgrades (debian) / dnf-automatic (rhel).
4. sysctl drop-in + apply.
5. Test tay từng hàm trong container ubuntu:24.04 và rockylinux:9.

## Success Criteria
- [x] Firewall active chỉ mở đúng EFFECTIVE_PORT — **cả khi không truyền `--port`** (run mặc định cũng có firewall)
- [x] Đổi port: port cũ bị đóng SAU verify (ufw status / firewall-cmd --list-all không còn port cũ)
- [x] Re-run với port khác: không tích lũy stale rule (chỉ còn port mới nhất)
- [x] `fail2ban-client status sshd` active; banaction khớp firewall backend thật
- [x] Timer auto-update active trên debian/rhel
- [x] `sysctl net.ipv4.tcp_syncookies` = 1 sau apply
- [x] Chạy lại: không duplicate rule, exit 0

## Risk Assessment
- epel-release không có trên RHEL thật (khác Rocky/Alma) → signal: `dnf install epel-release` fail → response: warn + skip fail2ban, ghi README.
- ufw enable cắt phiên hiện tại nếu port sai → luôn `allow` TRƯỚC `enable`, orchestrator truyền đúng EFFECTIVE_PORT.
- sysctl key không tồn tại trên kernel lạ → `sysctl --system || warn`, không die.
- fail2ban journalmatch stock có thể miss `sshd-session`/`ssh@.service` (OpenSSH ≥ 9.8, socket mode) → phase 5 functional ban test quyết định có cần journalmatch custom không.
- Arch/openSUSE không đạt được "firewall active"/"auto-update" criteria → criteria được viết theo family (có managed tool thì phải active; không có thì documented skip), không phải unconditional.
