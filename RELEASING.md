# Releasing hypershunt

This is the maintainer runbook for cutting a release.  For everyday
build/test/packaging commands see [`BUILD.md`](BUILD.md).

## Overview

Releases are **tag-driven**.  Pushing a `vX.Y.Z` tag triggers
`.github/workflows/release.yml`, which builds the multi-arch container
images and the `.deb`/`.rpm` packages, generates release notes, and opens
a **draft** GitHub Release.  The maintainer's job is therefore small:

1. Bump the version and commit it.
2. Tag and push.
3. Review and publish the draft Release that CI created, and publish the
   crate to crates.io.

## Versioning

The `version` field in `Cargo.toml` is the single source of truth.  On
`cargo build`, `build.rs` automatically:

- syncs the man-page `.TH` version in `docs/hypershunt.1` to the crate
  version, and
- regenerates `docs/manual.md` from the man page (via `pandoc`).

**Caveat:** the *date* in `docs/hypershunt.1`
(`.TH HYPERSHUNT 1 "YYYY-MM-DD" ...`) is **hand-maintained** — update it
yourself when you bump the version; `build.rs` does not touch it.

Tag scheme: `vMAJOR.MINOR.PATCH` with an optional pre-release suffix, e.g.
`v1.0.0-rc10` or `v1.0.0`.  This must match the workflow trigger pattern
`v[0-9]+.[0-9]+.[0-9]+*`.  Tags are lightweight (not signed) and point at
commits on `main`.

## Pre-release checklist

Run from a clean checkout of `main` with all intended changes merged:

```sh
cargo build                         # auto-syncs man page + docs/manual.md
cargo test                          # all unit tests must pass
./tests/integration/smoke.sh        # containerized integration suite (podman)
git diff --exit-code docs/hypershunt.1 docs/manual.md
```

The last command is the same gate CI enforces in
`.github/workflows/build.yml`: a non-empty diff means the man page or its
Markdown mirror is stale and was not rebuilt + committed.

## Cut the release

1. Edit `Cargo.toml` — set the new `version`.
2. Update the date in `docs/hypershunt.1` (`.TH ... "YYYY-MM-DD" ...`).
3. Update the version in the `README.md` status line (`> **Status:**
   ... (currently X.Y.Z)`).
4. Regenerate the man page and manual:

   ```sh
   cargo build
   ```

5. Commit the bump (include all four files):

   ```sh
   git add Cargo.toml docs/hypershunt.1 docs/manual.md README.md
   git commit -m "release: bump version to X.Y.Z"
   ```

6. Tag and push:

   ```sh
   git tag vX.Y.Z
   git push origin main vX.Y.Z
   ```

## What CI does on the tag

`.github/workflows/release.yml` runs automatically on the pushed tag:

- **Build matrix:** amd64 on `ubuntu-latest`, arm64 on `ubuntu-24.04-arm`.
- **Container images:** builds from `packaging/oci/Containerfile` and
  pushes arch-tagged images to `ghcr.io/<owner>/hypershunt:<version>-<arch>`,
  then assembles multi-arch manifests for both `:<version>` and `:latest`.
- **Distro packages:** extracts the compiled binary from the image and
  repackages it with `cargo deb` and `cargo generate-rpm` (no second
  compile).  Pre-release separators are sanitized per format — Debian
  turns `-` into `~`, RPM turns `-` into `_`.
- **Checksums:** writes `SHA256SUMS` over the `.deb` / `.rpm` artifacts.
- **Release notes:** runs `scripts/release-notes.sh "$VERSION"`, which
  builds a Conventional-Commits changelog since the previous `v*` tag and
  appends the Features/Standards sections lifted from `README.md`.
- **GitHub Release:** creates a **draft** release titled
  `hypershunt vX.Y.Z` with the `.deb`, `.rpm`, and `SHA256SUMS` attached.

## Publish

Once the workflow finishes, the container images are already live on
`ghcr.io`.  Open the **draft** GitHub Release, review the generated notes
and attached assets, and publish it to finalize.

Then publish the crate to crates.io (one-time `cargo login` with an API
token from <https://crates.io/me> first):

```sh
cargo publish --dry-run    # verification build; inspect the file list
cargo publish              # immutable — versions can be yanked, never deleted
```

Do this only after the GitHub Release is published, so the git tag the
crate's `repository` points at already exists.

## Local packaging (optional)

To build packages locally outside CI — e.g. to test packaging changes —
use the commands documented in [`BUILD.md`](BUILD.md#packaging):

- Debian: `cargo deb` (needs `cargo-deb`)
- RPM: `cargo build --release && cargo generate-rpm` (needs
  `cargo-generate-rpm`)
- Container: `packaging/oci/build.sh` (needs `podman`)
