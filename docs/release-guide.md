# Release & Tagging Guide

How a new version of `vps-hardening` reaches users. The one-liner in
`README.md` pins a tag, so the tag **is** the release contract: the tarball
URL and the raw `install.sh` URL both resolve from it.

## Versioning

Plain semver tags: `vMAJOR.MINOR.PATCH` (`v1.0.0`, `v1.0.1`, …).

- **PATCH** — fixes that don't change flags or behavior contracts
  (e.g. installer bug fixes).
- **MINOR** — new flags, new supported distros, new opt-in behavior.
- **MAJOR** — removed/renamed flags, changed defaults, dropped distro support.

## Release checklist

1. **Green tests on the exact commit to be tagged:**

   ```bash
   bash tests/test-static.sh
   bash tests/test-container.sh          # full matrix, or at minimum:
   bash tests/test-container.sh ubuntu-24.04 2222   # socket + port path
   ```

2. **Update pinned references if the installer changed.** `install.sh`
   defaults `VPS_HARDENING_REF` to the tag users should fetch; the README
   quick-start URLs hardcode it too. Bump both to the tag you are about to
   create, commit, and include that commit in the release.

3. **Commit, tag annotated, push both:**

   ```bash
   git push origin main
   git tag -a vX.Y.Z -m "short release summary"
   git push origin vX.Y.Z
   ```

4. **E2E-verify the published URLs** (CDN can lag a few minutes on a fresh
   tag; retry rather than assuming failure):

   ```bash
   curl -fsSL "https://github.com/anhvandev/vps-hardening/archive/refs/tags/vX.Y.Z.tar.gz" | tar -tz | head
   curl -fsSL "https://raw.githubusercontent.com/anhvandev/vps-hardening/vX.Y.Z/install.sh" | bash -n
   ```

   Then one real container run of the README one-liner before announcing.

## Rules

- **A pushed tag is immutable, forever.** raw.githubusercontent.com caches
  per-URL for minutes to hours; anyone who fetched the tag during that
  window runs different code than later fetchers. Never delete-and-recreate
  or move a published tag. A bad release is superseded by the next tag, not
  repaired in place.
- **Never publish a tag pointing at unreleased or failing code** — users
  pipe this straight into `sudo bash` on production machines.
- Deleting a published tag
  (`git push origin :refs/tags/vX.Y.Z && git tag -d vX.Y.Z`) is reserved
  for a release so broken it endangers machines *and* nobody has plausibly
  consumed it yet. Prefer a superseding patch tag in all other cases.
- Pre-release tags (`vX.Y.Z-rc1`) are fine for testing the pipeline itself;
  keep them off the README.
