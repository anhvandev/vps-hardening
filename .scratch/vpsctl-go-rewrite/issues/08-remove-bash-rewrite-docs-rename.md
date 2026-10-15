# Remove bash implementation, rewrite docs, rename repo

Status: ready-for-human
Milestone: M1
Blocked by: 06, 07

## What
- Delete `vps-hardening.sh`, `lib/`, `tests/test-static.sh`, old `tests/test-container.sh` (replaced in 06). Keep `plans/` as history.
- Rewrite `README.md` and `docs/release-guide.md` for `vpsctl`.
- Human: rename GitHub repo `vps-hardening` → `vpsctl` (GitHub redirects old URLs), cut the first `vpsctl` release.

## Comments

Agent part done on `vpsctl-go-rewrite` @ 2c18508 (bash removed, README + release-guide rewritten). Remaining human: rename GitHub repo to `vpsctl`, cut `v2.0.0` release.
