# Contributing to hypershunt

Thanks for your interest in improving hypershunt.  Bug reports, fixes,
documentation, and features are all welcome.  By submitting a contribution
you agree that it is licensed under the project's [BSD 2-Clause](LICENSE)
license, the same terms as the rest of hypershunt.

## Prerequisites

- **Rust 1.96 or newer** (edition 2024).  Install via [rustup](https://rustup.rs).
- **`libpam0g-dev`** — required to build; hypershunt links against PAM.

Two tools are needed only for specific tasks:

- **`pandoc`** — only to regenerate the man-page Markdown mirror (see below).
- **`podman`** — only to run the integration suite.

See [BUILD.md](BUILD.md) for the full prerequisite and packaging matrix.

## Build and test

```sh
cargo build
cargo test
```

All unit and doc tests must pass before you open a pull request.  The larger
end-to-end suite lives in [`tests/integration/smoke.sh`](tests/integration/smoke.sh)
and needs `podman`; [BUILD.md](BUILD.md) documents how to run it.

## Code style

- **Format for 80 columns.**  Run `cargo fmt`; this is enforced by
  `rustfmt.toml` (`max_width = 80`).
- **No `unwrap()` in production paths.**  Use `?` or explicit error handling.
  `unwrap()`/`expect()` are fine in tests.
- **Add a unit test for every new behaviour.**
- **Comments explain _why_, not _what_.**  Skip the obvious ones.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org), e.g.
`fix: reject empty Host header` or `feat(proxy): add least-conn balancing`.
Release notes are generated from commit history, so the `type:` prefix is
load-bearing — `feat`, `fix`, `perf`, and breaking changes (`!`) all surface
in the changelog.

## Opening a pull request

Before you push, run through this checklist:

- [ ] Branch off the latest `main`.
- [ ] `cargo fmt` leaves no changes.
- [ ] `cargo test` is green.
- [ ] If you changed the CLI or man page (`docs/hypershunt.1`), run
      `cargo build` and commit the regenerated `docs/manual.md`.  CI fails any
      PR where the two drift (`git diff --exit-code docs/hypershunt.1
      docs/manual.md`).
- [ ] Keep the PR focused on a single change; split unrelated work.

CI runs `cargo build`, the docs-sync check, `cargo test`, and the integration
suite on every PR to `main`.

## Reporting issues

File bugs and feature requests at
<https://github.com/MichaelPaddon/hypershunt/issues>.  For a bug, please
include the hypershunt version (`hypershunt --version`), a minimal config
snippet (`hypershunt.kdl`), and the steps to reproduce.
