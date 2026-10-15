# Release & Tagging Guide

How a new `vpsctl` version reaches users. Pushing a `v*` tag runs
`.github/workflows/release.yml`. It runs `go test ./...` and
`tests/test-install.sh`, builds static `vpsctl-linux-amd64` and
`vpsctl-linux-arm64` (`CGO_ENABLED=0`, version set from the tag), and
publishes them with `sha256sums.txt` to the GitHub release. `install.sh`
downloads exactly these assets.

## Versioning

Semver tags: `vMAJOR.MINOR.PATCH`.

- **PATCH**: fixes that don't change flags or behavior.
- **MINOR**: new flags, new distros, new opt-in behavior.
- **MAJOR**: removed/renamed flags, changed defaults, dropped distros.

## Release checklist

1. **Tests are green on the exact commit you will tag:**

   ```bash
   go test ./...
   bash tests/test-install.sh
   bash tests/test-container.sh                    # full matrix, or at least:
   bash tests/test-container.sh ubuntu-24.04 2222  # socket + port change
   ```

2. **Bump the pinned default tag in `install.sh`.** `VPSCTL_VERSION`
   defaults to a hardcoded tag (`VERSION=${VPSCTL_VERSION:-vX.Y.Z}` and the
   usage comment). Set it to the tag you are about to create. Update the
   one-liner URLs in `README.md` too. Commit this before tagging, so the
   `install.sh` at the tag downloads its own release.

3. **Create an annotated tag and push it:**

   ```bash
   git push origin main
   git tag -a vX.Y.Z -m "short release summary"
   git push origin vX.Y.Z
   ```

   Wait for the `release` workflow to go green.

4. **Check the published release end to end.** The CDN can take a few
   minutes on a new tag; retry before you assume it failed.

   ```bash
   curl -fsSL "https://raw.githubusercontent.com/anhvandev/vpsctl/vX.Y.Z/install.sh" | bash -n
   curl -fsSL "https://github.com/anhvandev/vpsctl/releases/download/vX.Y.Z/sha256sums.txt"
   ```

   Then run the README one-liner once in a throwaway container or VM
   before you announce the release.

## Rules

- **A pushed tag never changes.** raw.githubusercontent.com caches URLs,
  so people who fetched the old tag would run different code. Never
  delete and re-create a published tag, and never move it. Fix a bad
  release with a new patch tag.
- **Never tag untested or failing code.** Users pipe `install.sh` straight
  into `sudo bash` on production machines.
- Delete a published tag only if the release is so broken it endangers
  machines *and* nobody has likely used it yet. In every other case,
  publish a new patch tag instead.
- Pre-release tags (`vX.Y.Z-rc1`) are fine for testing the pipeline. Keep
  them out of the README.
