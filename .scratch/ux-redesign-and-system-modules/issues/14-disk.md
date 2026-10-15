# 14: Disk screen and cleanup

**What to build:** A Disk screen (design §8): usage bars per mounted filesystem and the largest directories under a chosen mount (bounded depth, skipping pseudo filesystems), with a cancellable scan. Cleanup actions each show reclaimable space before running and run as Tasks: vacuum the journal to N MB, clean the package cache, remove old kernels (keep the running one and one previous; dangerous confirm).

**Blocked by:** 02, 03

**Status:** ready-for-agent

- [ ] No arbitrary file or directory deletion anywhere on this screen.
- [ ] The running kernel can never be selected for removal.
- [ ] Unit tests with scripted df/du/journal/package output; `teatest`: cancel a scan, run a cleanup as a Task.
