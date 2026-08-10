# Brainstorm: VPS Initial-Hardening Script (multi-distro)

- **Date:** 2026-08-10
- **Status:** Contract accepted — ready for `/ak:plan`
- **Evidence:**
  - [Ubuntu research](research-260810-0028-ubuntu-ssh-hardening.md)
  - [Multi-distro research](research-260810-0028-other-distros-ssh-hardening.md)

## 1. Brainstorm Contract

### Outcome
Một bash script (`vps-hardening.sh`) chạy trên VPS mới khởi tạo, với quyền root:

1. Tạo user mới, thêm vào group admin (`sudo` hoặc `wheel` theo distro).
2. Tự sinh cặp key **ed25519**, cài public key cho user mới, in private key **đúng 1 lần** để operator lưu.
3. Chuyển SSH sang **key-only**: tắt `PasswordAuthentication` + `KbdInteractiveAuthentication`, `PermitRootLogin no`.
4. Tùy chọn đổi port SSH (tham số), xử lý đúng cả socket-activation lẫn SELinux.
5. Khóa (lock) user cloud mặc định (`ubuntu`/`debian`/`rocky`/... theo danh sách ứng viên).
6. Full hardening suite: firewall (UFW/firewalld) chỉ mở port SSH, fail2ban, auto security updates, sysctl hardening cơ bản.
7. Tự thích ứng distro qua **feature-detection**, không hardcode version.

### Constraints
- Bash thuần + coreutils/systemd; không ansible, không phụ thuộc ngoài repo.
- Chạy với root; phải **idempotent** (chạy lại không lỗi, không nhân đôi config).
- **Không bao giờ tự khóa máy:** `sshd -t` validate trước khi apply; giữ phiên hiện tại; yêu cầu operator xác nhận đã login được bằng user mới trước khi khóa user mặc định (hoặc chế độ `--yes` cho automation có cảnh báo rõ).
- Không override crypto algorithm trên RHEL-family (để crypto-policies DEFAULT quyết định).
- Drop-in sshd đặt tên `00-*.conf` (first-match-wins, phải sort trước `50-cloud-init.conf`).
- Reload/restart đúng theo daemon model: **Debian 13 socket mode cấm `reload`** (bug #1128329 — rebind conflict làm sshd chết); đổi port trên socket mode phải `daemon-reload && restart ssh.socket`.

### Non-goals
- Giám sát, VPN, SSH 2FA, hardening app cụ thể, kernel livepatch.
- Hỗ trợ distro ngoài danh sách đã research (Ubuntu, Debian, RHEL-family, Fedora, openSUSE, Arch).
- Xóa hẳn user mặc định (chỉ lock).

### Acceptance Criteria
Sau khi chạy trên mỗi distro hỗ trợ (tối thiểu Ubuntu 22.04, 24.04, Debian 12, 13, Rocky/Alma 9):
- [ ] Login thành công bằng user mới + key (cả port mới nếu đổi).
- [ ] `ssh -o PreferredAuthentications=password` bị từ chối; root login bị từ chối.
- [ ] `sshd -T` xác nhận: `passwordauthentication no`, `kbdinteractiveauthentication no`, `permitrootlogin no`.
- [ ] User mặc định bị lock (`passwd -S` → L, shell = nologin, authorized_keys rỗng).
- [ ] Firewall active, chỉ mở port SSH.
- [ ] fail2ban sshd jail active (kiểm `fail2ban-client status sshd`).
- [ ] Auto-update timer active (`unattended-upgrades` / `dnf-automatic.timer`).
- [ ] Trên SELinux: `getenforce` = Enforcing và key auth vẫn hoạt động (restorecon đúng).
- [ ] Chạy script lần 2: exit 0, không duplicate config.

## 2. Design Decision (từ research)

### Detection model — feature-detect, không parse version
```bash
. /etc/os-release                                  # ID, ID_LIKE
FAMILY: debian | rhel (từ ID/ID_LIKE =~ rhel|fedora)
SSH_UNIT: ssh (debian) | sshd (rhel/fedora/suse/arch)
SOCKET_MODE: systemctl is-active ssh.socket|sshd.socket
SELINUX: getenforce != Disabled
```

### Branch matrix cốt lõi
| Trục | Debian/Ubuntu | RHEL-family | Ghi chú |
|---|---|---|---|
| Admin group / user tool | `sudo` / `adduser --disabled-password` | `wheel` / `useradd` | openSUSE, Arch theo nhánh rhel-like (wheel) |
| Firewall | ufw | firewalld | no-op + warn nếu không có |
| fail2ban | apt, default OK | EPEL + `backend=systemd` | |
| Auto-update | unattended-upgrades | dnf-automatic | |
| SELinux | — | `restorecon -Rv ~/.ssh`; đổi port → `semanage port` | |
| Default users to lock | ubuntu, debian | rocky, almalinux, cloud-user, centos, ec2-user, fedora | lặp qua candidate list, `id -u` check |

### Lock-safe flow (bắt buộc theo thứ tự)
```
preflight (root, os-release, detect modes)
→ tạo user + sudo/wheel + key pair
→ viết 00-hardening.conf + sshd -t + sshd -T verify
→ firewall mở port mới TRƯỚC khi đổi port sshd
→ apply (socket: daemon-reload + restart socket | service: restart; KHÔNG reload trên Debian 13 socket)
→ IN HƯỚNG DẪN: mở phiên mới kiểm tra login + sudo
→ xác nhận OK → lock default users
→ fail2ban, auto-update, sysctl
→ tóm tắt + private key đã in 1 lần
```

### Phát hiện quan trọng nhất (rủi ro nếu bỏ qua)
1. `00-` không phải `99-` cho drop-in sshd (first-match-wins vs `50-cloud-init.conf`).
2. Ubuntu ≥24.04 & Debian 13 fresh: socket activation — restart `ssh.socket` mới đổi port.
3. Debian 13 socket: `reload ssh` = giết sshd.
4. RHEL: thiếu `restorecon` → key auth chết âm thầm dù permission đúng; thiếu `semanage port` → sshd không bind port mới.
5. Fedora 40+ xóa hẳn `sshd.socket` — detect bằng `is-active`, không suy từ tên distro.

## 3. Approaches đã cân nhắc

| Approach | Trade-off | Quyết định |
|---|---|---|
| **A. Một bash script, feature-detect** | Vừa đủ; rủi ro: ma trận distro lớn khó test hết | **CHỌN** — đúng scope, rẻ nhất để bỏ/sửa |
| B. Cloud-init user-data / Ansible role | Chuẩn infra hơn nhưng thêm dependency, không khớp "chạy tay lúc mới tạo VPS" | Loại |
| C. Chỉ Ubuntu (scope ban đầu) | Đơn giản nhất nhưng user đã mở rộng scope sang đa-distro bằng research thứ 2 | Loại — user chọn đa-distro |

## 4. Unresolved Questions
- Ma trận test thực tế: không có VPS thật/container của mọi distro — acceptance sẽ verify bằng review + (nếu có) container test với systemd. Cần quyết ở plan phase: test bằng gì?
- firewalld không cài sẵn trên một số minimal image: script **no-op + warn** hay **cài mới**? (đề xuất: cài trên rhel-family nếu thiếu, no-op trên Arch).
- sysctl hardening "cơ bản" gồm chính xác những key nào — chốt danh sách tối thiểu ở plan (đề xuất: `net.ipv4.ip_forward=0`, TCP SYN cookies, ICMP redirect off, rp_filter).

## Handoff
→ `/ak:plan` với contract trên + 2 research reports làm evidence. Output kỳ vọng: `vps-hardening.sh` (modular hóa nếu >200 dòng theo dev rules).
