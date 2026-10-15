# 16: Docker actions and image prune

**What to build:** From the Docker screen the operator starts, stops and restarts a container (Tasks, normal confirm) and opens its logs with follow. The Disk screen gains "Prune dangling Docker images" with reclaimable size, run as a Task.

**Blocked by:** 02, 14, 15

**Status:** ready-for-agent

- [ ] Only dangling images are pruned; no containers, volumes or tagged images removed.
- [ ] Leaving the logs view stops the follow process.
- [ ] `teatest`: restart as a Task; logs follow; prune shown only when Docker exists.
