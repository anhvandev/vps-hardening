# 13: Swap screen

**What to build:** A Swap screen (design §9) showing current swap (files and partitions) and RAM. The operator creates vpsctl's own swapfile with a suggested size (= RAM, max 4 GB), resizes it, or removes it; changes persist across reboot. Existing swap partitions are read-only. Overview's Resources card gains a Swap line with `[ Create swap ]` when there is none.

**Blocked by:** 02, 03

**Status:** resolved

- [x] Remove/shrink refused when swap in use exceeds free RAM (OOM risk), with the reason shown.
- [x] Remove is a dangerous confirm; create/resize normal.
- [x] Not enough free disk for the requested size → refused before writing anything.
- [x] Unit tests with temp root (fstab, swapfile) and scripted swap commands; container matrix only where swap is permitted.

## Comments

Resolved on `feat/ux-redesign` @ 6d5bbf5 (merge). Code-review fixes in aa00873.
