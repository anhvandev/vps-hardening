---
phase: 2
title: "SSH hardening + daemon apply"
status: pending
priority: P1
effort: "5h"
dependencies: [1]
---

# Phase 2: SSH hardening + daemon apply

## Overview
`lib/sshd.sh`: drop-in `00-hardening.conf` **hai giai đoạn** (port trước, auth-hardening sau verify gate), validate (`sshd -t`, `sshd -T` + `-C`), apply đúng daemon model với snapshot-rollback, xử lý đổi port (SELinux `semanage`, socket generator probe). Trái tim chống-lockout.

## Requirements
- Functional:
  - **Effective port derive từ live state, không từ flags:** `EFFECTIVE_PORT = --port nếu có; else parse Port từ 00-hardening.conf hiện có; else sshd -T | awk '/^port /{print $2}'; else 22`. Flagless re-run KHÔNG được revert port đã set trước đó.
  - **Stage A drop-in** (chỉ port, nếu đổi): `/etc/ssh/sshd_config.d/00-hardening.conf` chứa chỉ `Port <P>`.
  - **Stage B drop-in** (sau verify gate): thêm auth-hardening:
    ```
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PubkeyAuthentication yes
    PermitRootLogin no
    ```
  - Pre-check: liệt kê `/etc/ssh/sshd_config.d/*.conf` lạ → warn; **scan `Match` block**: `grep -n '^[[:space:]]*Match' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf` → warn to (Match có thể re-enable password auth cho một số connection).
  - Assert `Include /etc/ssh/sshd_config.d/*.conf` tồn tại; thiếu → append Include lên ĐẦU file.
  - `validate_sshd`: `sshd -t` + `sshd -T | grep -Ei '^(passwordauthentication|kbdinteractiveauthentication|permitrootlogin|port) '` + **`sshd -T -C user=<newuser>,host=localhost,addr=127.0.0.1`** (bắt Match-block divergence); assert giá trị đúng.
  - `snapshot_state` / `rollback_state`: backup `00-hardening.conf` cũ (nếu có) + trạng thái firewall SSH rules trước mutation; mọi failure sau apply → restore snapshot + re-apply daemon state cũ trước khi exit.
  - `apply_sshd`:
    - Đổi port + SELINUX → `semanage port -a -t ssh_port_t -p tcp <P>` (fallback `-m` nếu tồn tại); cần `policycoreutils-python-utils` (rhel) — cài nếu thiếu.
    - SOCKET_MODE=true → `systemctl daemon-reload && systemctl restart ssh.socket` (đổi port) hoặc `systemctl restart "$SSH_UNIT"` (không đổi port). **TUYỆT ĐỐI không `reload`** (Debian 13 bug #1128329).
    - **Socket generator probe (bắt buộc, không defer):** sau daemon-reload, `systemctl cat ssh.socket | grep -q "ListenStream.*<P>"`; nếu generator KHÔNG sinh port mới (Debian 13 chưa confirm có generator) → viết manual drop-in `/etc/systemd/system/ssh.socket.d/99-hardening-listen.conf` (`[Socket]\nListenStream=\nListenStream=<P>`), daemon-reload + restart socket lại.
    - SOCKET_MODE=false → `systemctl restart "$SSH_UNIT"`; fallback `service "$SSH_UNIT" restart`.
    - Sau apply: `verify_listener <P>` — **field-exact**: `ss -ltnH "sport = :$P"` (không substring grep, `:22` match cả `:2222`); retry 3 lần; fail → rollback_state + die.
    - Đổi port: assert thêm port cũ KHÔNG còn listen sau khi stage B hoàn tất.
- Non-functional: idempotent (drop-in diff vs live effective config, giống → skip restart); không override Ciphers/MACs/KexAlgorithms trên FAMILY=rhel (crypto-policies DEFAULT quyết định).

## Architecture
```
snapshot_state
→ write_dropin stage A (port only) → validate → apply → verify_listener (field-exact)
   → generator probe fallback nếu socket mode
→ [orchestrator: verify gate — user chứng minh login mới được]
→ write_dropin stage B (auth hardening) → validate (gồm -C) → apply → verify_listener
→ [orchestrator: firewall_close_old_ssh]
→ fail → rollback_state
```
Generator chỉ xác nhận cho Ubuntu 24.04+ (`sshd-socket-generator`, Ubuntu packaging). Debian 13 CHƯA có evidence có generator → probe runtime bắt buộc, manual socket drop-in là fallback chính thức trong phase này (không defer sang phase 5).

## Related Code Files
- Create: `lib/sshd.sh`
- Modify: (sau) `vps-hardening.sh` gọi module

## Implementation Steps
1. `effective_port` — derive từ flags/existing drop-in/`sshd -T`.
2. `snapshot_state`/`rollback_state`.
3. `write_dropin STAGE` — stage A/B deterministic.
4. `validate_sshd` — sshd -t + sshd -T + sshd -T -C; Match scan.
5. `apply_sshd` — nhánh socket/service; generator probe + manual socket fallback; KHÔNG reload.
6. `verify_listener PORT` — `ss -ltnH "sport = :$P"`, retry 3, fail → rollback.
7. Static grep-guard: không `reload` trên ssh unit; không substring `grep :PORT` (dùng sport filter).

## Success Criteria
- [x] `sshd -T` + `sshd -T -C user=...` ra đúng passwordauthentication no / kbdinteractiveauthentication no / permitrootlogin no / port đúng
- [x] Flagless re-run giữ nguyên custom port đã set trước đó (không revert về 22)
- [x] Đổi port trên socket mode: `ss -ltnH 'sport = :2222'` thấy port mới; port 22 mất sau stage B; generator-missing → manual socket drop-in hoạt động
- [x] verify_listener fail → snapshot được restore, daemon về trạng thái trước run
- [x] Debian 13 (container): không có đường code nào gọi `systemctl reload ssh`
- [x] Chạy lại cùng config: không restart lại (idempotent)

## Risk Assessment
- `KbdInteractiveAuthentication` là OpenSSH 8.2+; EL8 ship 8.0p1 — defer-note: thêm rockylinux:8/almalinux:8 vào test matrix (phase 5) để kiểm chứng; nếu fail → gate keyword theo `sshd -T` probe, fallback `ChallengeResponseAuthentication no`.
- `sshd -T` cần hostkey tồn tại → pre-check `ls /etc/ssh/ssh_host_*` hoặc `ssh-keygen -A` trước validate.
- Match block trong config provider re-enable password auth cho một số connection → Match scan + `-C` check (đã vào requirements).
- Lockout nếu phiên hiện tại là password-auth và config áp ngay → stage A chỉ đụng port; auth-hardening chỉ apply sau verify gate (phase 4 orchestrates).
