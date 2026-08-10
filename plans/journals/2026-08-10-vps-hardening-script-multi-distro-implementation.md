---
title: VPS hardening script multi-distro implementation
date: 2026-08-10
summary: "Multi-distro VPS initial-hardening bash script: 5 phases, 6/6 container matrix, 2 review rounds, SHIP"
---

# VPS hardening script multi-distro implementation

# VPS Hardening Script — Multi-Distro Implementation

Plan: plans/260810-0051-vps-hardening-script (5/5 phases, 38/38 tasks via ak plan)
Report: plans/reports/cook-260810-vps-hardening-script.md

## What was built
Orchestrator vps-hardening.sh + lib/{logging,detect,user,sshd,firewall,services}.sh + tests/ + README.md. Executed in --auto mode.

## Phases
1. Core libs (logging, detect, user)
2. sshd two-stage drop-in hardening
3. Firewall / fail2ban / sysctl
4. Lock-safe orchestrator (rollback, snapshots)
5. Tests + docs

## Verification
- shellcheck clean, bash -n clean, static guards pass
- systemd container matrix 6/6: ubuntu:22.04/24.04, debian:12/13, rockylinux:8/9
- Pre-state socket assertions, port-change cases on socket distros
- Functional fail2ban ban test, idempotency + flagless re-run port retention
- Log private-key safety confirmed

## Bugs caught by matrix and fixed
1. `sshd -T | grep -q` SIGPIPE under pipefail → capture output before grep
2. `mv` over existing file returns 1 on EL8 coreutils → write with `cat >`
3. Function ending in false `&&` compound aborts under set -e → explicit `return 0`
4. Ubuntu 22.04 fail2ban needs backend=systemd (no rsyslog) and iptables-multiport (0.11.2 lacks nftables action)
5. /run/sshd must exist before `sshd -t` on Ubuntu 24.04

## Code review
2 rounds via code-reviewer subagent. Round 1: H1 (--skip-firewall + --port lockout gap → parse-time reject), H2 (rollback didn't restore firewall state → snapshot/purge added), M3 (ufw v6 rows), M4 (locale grep). All fixed and re-verified. Final verdict: SHIP.

## Status
Plan synced 5/5 phases, 38/38 tasks. User declined git commit.

## Unresolved
- SELinux manual verification on a real VM still pending (caveat recorded in README).

> Historical work record — not durable authority. Prefer docs/specs/ADRs for current decisions.
