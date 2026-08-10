---
title: "vps-hardening-script"
description: "Multi-distro VPS initial-hardening bash script: user+sudo, SSH key-only, lock default cloud user, firewall, fail2ban, auto-updates, sysctl"
status: completed
priority: P1
effort: "1-2d"
tags: [security, bash, vps, ssh]
created: 2026-08-10
---

# vps-hardening-script

## Overview

Một bộ script bash (modular, sourced từ `lib/`) chạy với root trên VPS mới khởi tạo. Tự thích ứng distro bằng **feature-detection** (không hardcode version): Ubuntu 22.04/24.04/25.x, Debian 11/12/13, Rocky/Alma 8/9/10, Fedora, openSUSE, Arch. Chống lockout bằng verify-then-cut.

**Contract nguồn:** [brainstorm report](../reports/brainstorm-260810-0028-vps-hardening-script.md)
**Evidence:** [Ubuntu research](../reports/research-260810-0028-ubuntu-ssh-hardening.md), [multi-distro research](../reports/research-260810-0028-other-distros-ssh-hardening.md)

## Goals

| # | Goal | Priority |
|---|------|----------|
| 1 | Tạo user mới + group admin (sudo/wheel) + ed25519 key, in private key 1 lần | P1 |
| 2 | SSH key-only via drop-in `00-hardening.conf` (first-match-wins), tùy chọn đổi port | P1 |
| 3 | Apply SSH đúng theo daemon model (service vs socket activation) — zero lockout | P1 |
| 4 | Lock user cloud mặc định theo candidate list | P1 |
| 5 | Hardening suite: firewall (ufw/firewalld), fail2ban, auto-update, sysctl | P2 |
| 6 | Idempotent + shellcheck clean + test matrix | P1 |

## Repo Layout (target)

```
vps-hardening.sh        # thin orchestrator, usage/flags, lock-safe flow
lib/
  detect.sh             # os-release, FAMILY, SSH_UNIT, SOCKET_MODE, SELINUX
  logging.sh            # info/warn/err/die, idempotent helpers
  user.sh               # create user, key pair, lock default users
  sshd.sh               # drop-in, validate, apply (service vs socket)
  firewall.sh           # ufw / firewalld
  services.sh           # fail2ban, auto-updates, sysctl
README.md               # usage, supported matrix, recovery guide
tests/
  test-static.sh        # shellcheck + bash -n
  test-container.sh     # systemd container matrix (ubuntu:22.04, ubuntu:24.04, debian:12, debian:13, rockylinux:9)
```

## Phases

| # | Phase | Status |
|---|-------|--------|
| 1 | [Core: detection + user + key](./phase-01-detection-user.md) | Done |
| 2 | [SSH hardening + daemon apply](./phase-02-ssh-hardening.md) | Done |
| 3 | [Firewall + fail2ban + auto-updates + sysctl](./phase-03-hardening-suite.md) | Done |
| 4 | [Lock-safe flow + orchestrator + idempotency](./phase-04-orchestrator-flow.md) | Done |
| 5 | [Tests + shellcheck + docs](./phase-05-tests-docs.md) | Done |

## Success Criteria

- [x] Trên ma trận test (ubuntu:22.04, ubuntu:24.04, debian:12, debian:13, rockylinux:9, rockylinux:8) với **pre-state socket assertions**: user mới login key-only OK, password auth từ chối, root login từ chối, `sshd -T` + `sshd -T -C` xác nhận 3 giá trị — **6/6 image pass** (test-container.sh)
- [x] User cloud mặc định bị lock (usermod -L, shell nologin, authorized_keys rỗng) + cloud-init drop-in `99-hardening.cfg` chặn re-inject key
- [x] Firewall active chỉ mở EFFECTIVE_PORT — **kể cả run mặc định không `--port`**; port cũ đóng sau verify; re-run không tích lũy stale rule (purge cả `(v6)` rows)
- [ ] SELinux (restorecon/semanage): **chưa verify tay trên VM thật** — README caveat đã ghi; container không enforce được (demote có chủ đích)
- [x] fail2ban sshd jail active + **functional ban test** (ban IP materialize trong iptables/nft/firewalld ipset thật); auto-update timer active
- [x] Idempotent: chạy lần 2 exit 0; **flagless re-run không revert custom port** (asserted trên ubuntu:24.04 + debian:13)
- [x] Key an toàn: in ra /dev/tty hoặc `--key-out`; log không chứa private key (grep test); `--rotate-key` tồn tại
- [x] Gate decline → exit 3 với password auth còn nguyên; `--yes` vẫn chạy pre-lock machine assertions (sshd -T -C, key perms, sudo -l, su)
- [x] `shellcheck` sạch (-S warning), `bash -n` pass, static guards (không `reload ssh`, không substring `grep :PORT`, libs không tự abort dưới `set -e`)
- [x] Non-systemd environment → die rõ ràng (preflight `[[ -d /run/systemd/system ]]`)

### Post-review fixes applied (code-reviewer, 2026-08-10)

| Finding | Fix |
|---|---|
| H1 `--skip-firewall --port` lockout gap | flag-parse time reject (exit 2) |
| H2 rollback không restore firewall state | snapshot_state lưu ufw/firewalld rules; rollback_state xóa rule mở sau snapshot |
| M3 ufw purge bỏ sót `(v6)` rows | strip suffix ` (v6)` trước khi delete |
| M4 ufw status grep locale-fragile | `grep -qi 'status: *active'` |

Bugs caught by the matrix during implementation: SIGPIPE trong pre_lock (`sshd -T | grep -q` → capture trước), `mv` overwrite rc=1 trên EL8 (→ `cat >`), `scan_match_blocks` exit-status landmine (→ explicit `return 0`), fail2ban Ubuntu 22.04 cần `backend = systemd` + `iptables-multiport` (0.11.2 chưa có nftables action), `/run/sshd` thiếu trên Ubuntu 24.04 pre-first-start.

## Key Risks

- **Debian 13 socket `reload` bug** (#1128329): script tuyệt đối không `reload` — luôn `restart`; socket mode đổi port phải `daemon-reload && restart ssh.socket` + **generator probe** (Debian 13 chưa confirm có generator → manual socket drop-in fallback bắt buộc).
- **50-cloud-init.conf override:** drop-in phải là `00-*.conf` (first-match-wins) + Match-block scan.
- **SELinux:** thiếu `restorecon`/`semanage port` → key auth chết âm thầm / sshd không bind port mới; không test được trong container.
- **Lockout ordering:** auth-hardening chỉ apply SAU verify gate (two-stage drop-in); firewall close-old chỉ sau verify_listener; snapshot-rollback khi apply fail.
- **Không có VPS thật để test mọi distro** → container systemd matrix + pre-state asserts là acceptance thay thế; README ghi rõ tested vs expected-to-work.

## Red Team Review

### Session — 2026-08-10
**Findings:** 24 raw → 21 unique sau dedupe (15 accepted+applied, 6 defer-as-notes — tất cả đã áp vào phase files)
**Severity breakdown:** 3 Critical, 9 High, 9 Medium
**Reviewers:** Security Adversary (8), Failure Mode Analyst (9), Assumption Destroyer (7)

| # | Finding | Severity | Disposition | Applied To |
|---|---------|----------|-------------|------------|
| 1 | Firewall không enable khi không có --port | Critical | Accept | Phase 3 (firewall_setup vô điều kiện), Phase 4 flow |
| 2 | Flagless re-run revert custom port → lockout | Critical | Accept | Phase 2 (effective_port từ live state), Phase 4 |
| 3 | firewalld remove port 22 trước khi sshd chứng minh port mới | Critical | Accept | Phase 3 (split open/close), Phase 4 flow |
| 4 | Hardening apply trước verify gate (ngược safe-rollout) | High | Accept | Phase 2 (two-stage drop-in), Phase 4 |
| 5 | Không rollback khi apply/verify fail | High | Accept | Phase 2 (snapshot_state/rollback_state), Phase 4 |
| 6 | detect.sh tự abort dưới set -euo pipefail | High | Accept | Phase 1 (if/then probes, return 0), Phase 5 static test |
| 7 | Debian 13 generator claim unverified | High | Accept | Phase 2 (runtime generator probe, fallback bắt buộc) |
| 8 | Key 1 lần + skip rerun = credential gap | High | Accept | Phase 1 (rotate_user_key), Phase 4 (--rotate-key, force reprint) |
| 9 | Private key lọt vào tee'd log | High | Accept | Phase 4 (/dev/tty, --key-out), Phase 5 (log grep test) |
| 10 | Non-systemd VPS không có nhánh | High | Accept | Phase 1 (systemd preflight die), Phase 4, README |
| 11 | Test không assert socket pre-state | High | Accept | Phase 5 (pre-state assert + force socket Dockerfile) |
| 12 | SELinux paths untestable nhưng là hard criteria | High | Accept | plan.md criteria (demote → verify tay + README caveat) |
| 13 | fail2ban thiếu banaction + journalmatch risk | Medium | Accept | Phase 3 (banaction per family), Phase 5 (functional ban test) |
| 14 | openSUSE wheel sudoers không provision | Medium | Accept | Phase 1 (generic wheel sudoers) |
| 15 | Thiếu Match-scan + sshd -T -C; --yes lock không verify | Medium | Accept | Phase 2 (-C + Match scan), Phase 4 (pre-lock assertions mọi path) |
| 16 | ss substring grep false match | Medium | Accept | Phase 2 (`ss -ltnH "sport = :"`), Phase 5 grep-guard |
| 17 | Socket detect chỉ is-active | Medium | Accept | Phase 1 (is-active OR is-enabled + list-unit-files) |
| 18 | cloud-init resurrect default-user keys | Medium | Accept | Phase 1 (99-hardening.cfg note) |
| 19 | EL8 KbdInteractiveAuthentication unverified | Medium | Accept | Phase 2 risk note + Phase 5 rockylinux:8 trong matrix |
| 20 | Support matrix > test matrix | Medium | Accept | Phase 5 README tested-vs-expected |
| 21 | Arch/openSUSE không đạt unconditional criteria | Medium | Accept | Phase 3 (criteria per-family), README |

### Whole-Plan Consistency Sweep
Đã re-read plan.md + 5 phase files sau khi áp: phases table, success criteria, flow (two-stage, open/close firewall split), flags list (--key-out, --rotate-key đã vào phase 4 flag list), matrix test (thêm rockylinux:8), generator probe (phase 2 chính thức, không defer), SELinux demote khớp plan.md + phase 5 + README note. Không còn contradiction chưa resolve.

<!-- slug: vps-hardening-script -->
