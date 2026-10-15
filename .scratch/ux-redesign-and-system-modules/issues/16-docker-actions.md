# 16: Docker actions and image prune

**What to build:** From the Docker screen the operator starts, stops and restarts a container (Tasks, normal confirm) and opens its logs with follow. The Disk screen gains "Prune dangling Docker images" with reclaimable size, run as a Task.

**Blocked by:** 02, 14, 15

**Status:** resolved

- [x] Only dangling images are pruned; no containers, volumes or tagged images removed.
- [x] Leaving the logs view stops the follow process.
- [x] `teatest`: restart as a Task; logs follow; prune shown only when Docker exists.

## Comments

Resolved on `feat/ux-redesign` @ db44d96 (merge). Code-review fixes in aa00873.
