# UI redesign — mockups

Status: approved (2026-10-15)

Decisions this draws on: grilling 2026-10-15 rounds 1–3 (Task, Hardening Status, Hardening Record, menu groups, two-tier confirms, sidebar layout, mouse, colors, shared keymap, auto-refresh). Vocabulary: `GLOSSARY.md`.

Legend: `▌` selected row · `[ … ]` clickable button · `●` green/ok · `⚠` yellow · `✗` red · `·` grey/n.a. · `◆` Lockout Guard protects this item (no emoji anywhere). Colors are described in brackets where they matter.

## 0. Frame (every screen)

```
┌ vpsctl ─ prod-sg-01 ─ Ubuntu 24.04 ─ 2 vCPU · 2 GB ────────── ● Hardening 9/9 ┐
│ SIDEBAR (24 cols)│ HEADER: screen title ······················· summary counts │
│                  │ BODY: table / form / viewport                               │
│                  │ DETAIL: box for the selected row (hidden if height < 30)    │
│                  │ ACTIONS: [ button ] [ button ]                              │
├──────────────────┴─────────────────────────────────────────────────────────────┤
│ LEFT: running Task / "locked by alice (pid 4120)"   RIGHT: screen keys · ? help │
└─────────────────────────────────────────────────────────────────────────────────┘
```

- Sidebar groups: SECURITY (Hardening, Firewall, SSH, fail2ban, Logins) · ACCESS (Users) · WORKLOADS (Services, Timers, Cron, Docker) · SYSTEM (Overview, Updates, Disk, Swap, Task history). Docker hidden when not installed.
- Width < 100: sidebar collapses to a one-line tab bar showing the current group; `tab` opens the sidebar as an overlay.
- Smaller than 80×24: only "terminal too small (need 80×24)".
- Header badge: `● Hardening 9/9` green · `⚠ Hardening 7/9` yellow · `✗ NOT HARDENED` red (SSH not key-only). Clicking it opens Hardening.

## 1. Overview (default screen, refresh 5s)

```
│ Overview                                                    refreshed 2s ago │
│ ╭ Security ────────────────────────╮ ╭ Resources ────────────────────────────╮│
│ │ Hardening   ⚠ 8/9  fail2ban off  │ │ CPU   ▇▇▇▁▁▁▁▁▁▁  31%   load 0.42    ││
│ │ SSH         ● key-only · :2222   │ │ RAM   ▇▇▇▇▇▇▁▁▁▁  1.2/2.0 GB          ││
│ │ Firewall    ● ufw · 6 rules      │ │ Swap  ·  none        [ Create swap ]  ││
│ │ Docker      ⚠ 1 Published Port   │ │ Disk /▇▇▇▇▇▇▇▇▁▁  41/50 GB  82%  ⚠    ││
│ │ Logins 24h  ● 3 ok · ✗ 214 failed│ │ Uptime 12d 4h                         ││
│ ╰──────────────────────────────────╯ ╰───────────────────────────────────────╯│
│ ╭ Updates ─────────────────────────╮ ╭ Services ─────────────────────────────╮│
│ │ 4 security · 11 other pending    │ │ ● 23 running   ✗ 1 failed: worker     ││
│ │ last auto-run 6h ago  ⚠ reboot   │ │ ⚠ 2 Timers missed last run            ││
│ ╰──────────────────────────────────╯ ╰───────────────────────────────────────╯│
```
Every card is clickable and opens its screen; warnings link to the exact item (e.g. "worker" opens that Service).

## 2a. Hardening — machine already hardened → Hardening Status

```
│ Hardening                         ran 2026-10-15 01:12 by root · Admin User anh │
│ ┌──────────────────────────────────────────────────────────────────────────────┐│
│ │ STEP                          STATE                                          ││
│ │ Admin User + key              ● Done        anh · 1 key                      ││
│ │ Key-only SSH, no root login   ● Done                                         ││
│ │ SSH port                      ● Done        2222          [ Change in SSH ]  ││
│ │ Firewall on                   ● Done        ufw                              ││
│ │ Default Cloud Users locked    ● Done        ubuntu                           ││
│ │ cloud-init re-injection block ● Done                                         ││
│ │▌fail2ban                      ⚠ Missing     was applied 2026-10-15  [ Apply ]││
│ │ Automatic security updates    ● Done        unattended-upgrades             ││
│ │ sysctl hardening              · Skipped     chosen at Hardening    [ Apply ]││
│ └──────────────────────────────────────────────────────────────────────────────┘│
│  [ Apply all missing ]                                                          │
```
States read live; "Skipped" and "was applied" come from the Hardening Record. There is no full re-run wizard here.

## 2b. Hardening — machine not hardened → wizard

```
│ Hardening                                                 ✗ NOT HARDENED       │
│  Admin user    [ anh                  ]   must not be root / ubuntu / system    │
│  SSH port      [ 2222                 ]   blank = keep 22                       │
│  Private key   (●) show once on screen   ( ) save to file [ /root/anh.key ]     │
│  Steps         [x] Firewall  [x] fail2ban  [x] Auto updates  [x] sysctl          │
│                                                                                 │
│  [ Start Hardening ]                                                            │
```

## 3. Task panel (overlay over any screen)

Running:
```
        ╭ Task: Hardening ───────────────────────────────── 01:12 elapsed ╮
        │ ✓ Admin User + key                                              │
        │ ✓ Firewall on                                                   │
        │ ⠋ SSH stage A (port 2222)                                       │
        │ · Verify Gate                                                   │
        │ · Key-only SSH                                                  │
        │ · fail2ban · Auto updates · sysctl                              │
        │ ─ output ────────────────────────────────────────────────────── │
        │ [*] wrote sshd drop-in (stage A, port 2222)                     │
        │ [*] restarting ssh.socket                                       │
        │ [*] listener confirmed on port 2222▌                            │
        │                     [ Hide ]  (keeps running in the status bar) │
        ╰─────────────────────────────────────────────────────────────────╯
```
Finished:
```
        ╭ Task: Hardening ─────────────────────────────── ✓ Done in 02:47 ╮
        │ SUMMARY  admin anh · ssh :2222 · password auth off · root off   │
        │          Default Cloud Users locked: ubuntu                     │
        │ [ View full output ]  [ Close ]                                 │
        ╰─────────────────────────────────────────────────────────────────╯
        ╭ Task: Install fail2ban ────────────────────────── ✗ Failed      ╮
        │ step 2/4 "apt install fail2ban": exit 100                       │
        │ E: Unable to locate package fail2ban                            │
        │ Nothing changed after step 1 (rolled back).                     │
        │ [ View full output ]  [ Close ]                                 │
        ╰─────────────────────────────────────────────────────────────────╯
```
Status bar while hidden: `⠋ Hardening · SSH stage A · 01:12   (click to open)`.

## 4. Firewall

```
│ Firewall                                          ufw · active · 6 rules       │
│ ┌──────────────────────────────────────────────────────────────────────────────┐│
│ │ PORT      PROTO  SOURCE        LISTENING          NOTE                       ││
│ │ 2222      tcp    any           ● sshd             SSH ◆                     ││
│ │▌443       tcp    any           ● caddy                                       ││
│ │ 5432      tcp    10.0.0.0/24   ● postgres                                    ││
│ │ 9000:9100 udp    any           · nothing                                     ││
│ │ 8080      tcp    (Docker)      ● docker-proxy     ⚠ Published Port, bypasses ││
│ └──────────────────────────────────────────────────────────────────────────────┘│
│ ╭ 8080/tcp ────────────────────────────────────────────────────────────────────╮│
│ │ Published by container web-1 (compose: shop). Reachable from the internet    ││
│ │ regardless of ufw. Fix: publish as 127.0.0.1:8080:80 and front it with a     ││
│ │ reverse proxy.                                      [ Open in Docker ]       ││
│ ╰──────────────────────────────────────────────────────────────────────────────╯│
│  [ + Open port ]  [ Remove ]  [ Refresh ]                                       │
```
Selecting the SSH row greys out `[ Remove ]` with the Lockout Guard reason shown in the detail box.

## 5. Users

```
│ Users                                            3 Managed Users · 2 with sudo │
│ │ USER     SUDO  KEYS  STATE    LAST LOGIN                                  │  │
│ │ anh (you) ●     2     ● active 2m ago                           ◆         │  │
│ │▌bob      ●     1     ● active 3d ago                                      │  │
│ │ deploy   ·     1     ⚠ locked never                                       │  │
│ ╭ bob ─────────────────────────────────────────────────────────────────────╮  │
│ │ keys: ed25519 SHA256:x9…Qa "bob-laptop"   [ Remove key ]                  │  │
│ ╰───────────────────────────────────────────────────────────────────────────╯  │
│  [ + New user ] [ + Add key ] [ Sudo on/off ] [ Lock ] [ Delete ]              │
```
Delete = dangerous confirm (type the user name).

## 6. Services (refresh 5s)

```
│ Services                  filter: [ running·enabled·failed ▾ ]  / [ ngi     ] │
│ │ UNIT              STATE        ENABLED  SINCE     NOTE                      │ │
│ │▌nginx             ● running    ●        12d                                 │ │
│ │ worker            ✗ failed     ●        3m        exit 1                    │ │
│ │ ssh               ● running    ●        12d       ◆ Protected Unit         │ │
│ ╭ nginx ───────────────────────────────────────────────────────────────────╮ │
│ │ vendor unit + override (2 lines) · mem 38 MB · pid 811                     │ │
│ ╰───────────────────────────────────────────────────────────────────────────╯ │
│ [ Start ][ Stop ][ Restart ][ Enable ][ Disable ][ Journal ][ Edit ][ + New ]  │
```

## 7. Docker (hidden when Docker missing, refresh 5s)

```
│ Docker                                       5 containers · ⚠ 1 Published Port │
│ │ CONTAINER        PROJECT  STATE       PORTS                    IMAGE        │ │
│ │ shop-web-1       shop     ● running   ⚠ 0.0.0.0:8080→80        nginx:1.27   │ │
│ │▌shop-db-1        shop     ● running   127.0.0.1:5432→5432      postgres:16  │ │
│ │ old-api          —        · exited(0) —                        api:0.3      │ │
│ [ Start ][ Stop ][ Restart ][ Logs ]                                           │
```

## 8. Disk

```
│ Disk                                                                          │
│ /        ▇▇▇▇▇▇▇▇▁▁  41/50 GB  82% ⚠      /boot ▇▇▁▁▁▁▁▁▁▁ 0.2/1 GB           │
│ ╭ Largest under /  (depth 3) ─────────────────── scanning… [ Cancel ] ╮       │
│ │ 18.2 GB  /var/lib/docker                                              │       │
│ │  9.1 GB  /var/log/journal                                             │       │
│ │  4.0 GB  /home/anh/backups                                            │       │
│ ╰───────────────────────────────────────────────────────────────────────╯       │
│ Cleanup                       reclaimable                                     │
│  Vacuum journal to 200 MB     8.9 GB        [ Run ]                            │
│  Clean apt cache              1.2 GB        [ Run ]                            │
│  Remove old kernels (keep 2)  0.6 GB        [ Run ]  dangerous confirm         │
│  Prune dangling Docker images 3.4 GB        [ Run ]                            │
```
No arbitrary file deletion.

## 9. Updates · Swap · Logins (compact)

```
│ Updates      4 security · 11 other · ⚠ reboot required (kernel 6.8.0-49)       │
│ │ PACKAGE        CURRENT → NEW          KIND      │                            │
│ │ openssl        3.0.13-0 → 3.0.13-1    security  │                            │
│ [ Install security ]  [ Install all … ]  [ Reboot … ]                          │

│ Swap         none · RAM 2 GB                                                   │
│  Size [ 2 GB ▾ ]  (suggested = RAM, max 4 GB)        [ Create swapfile ]       │

│ Logins       window: (●) 24h ( ) 7d                                             │
│ │ TIME    USER  FROM            RESULT │  Top failing IPs: 45.x.x.12  88       │
│ │ 10:02   anh   113.161.x.x     ● ok   │                   103.x.x.7  41       │
│ │ 09:58   root  45.x.x.12       ✗ fail │                                       │
```

## 10. Confirm dialogs

```
   ╭ Restart nginx? ─────────────╮      ╭ Delete user bob ─────────────────────╮
   │        [ Yes ]  [ No ]      │      │ Home /home/bob: (●) keep  ( ) delete │
   ╰─────────────────────────────╯      │ Type "bob" to confirm: [ bo▌      ]  │
         normal: y/N                    │              [ Delete ]  [ Cancel ]  │
                                        ╰──────────────────────────────────────╯
                                               dangerous: type the target name
```
Lockout Guard refusals are not dialogs: the button is disabled and the reason is shown in the detail box or the status bar.

## Interaction notes
- Mouse: click sidebar / rows / buttons / tabs / header badge / Overview cards; wheel scrolls tables and viewports. `m` toggles mouse capture; help says "Shift+drag to select text".
- Keys: `↑↓/jk` move · `enter` open · `esc` back · `/` filter · `r` refresh · `a` add · `d` delete · `e` edit · `?` help · `q` quit. Screen-specific keys always shown in the status bar.
- Colors: one adaptive accent; green ok · yellow warn/Missing · red error/blocked · grey n.a.; readable on 16 colors; ASCII fallbacks for `● ✓ ✗ ⚠ ▶ ◆`.
