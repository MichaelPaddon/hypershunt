# Building hypershunt

hypershunt is a standard Cargo project. Building the binary needs a Rust
toolchain plus a few system libraries; packaging and the container image
need a couple of extra tools.

## Prerequisites

- **Rust** — a recent stable toolchain. The crate uses edition 2024, so
  Rust 1.85 or newer. Install via [rustup](https://rustup.rs).
- **System libraries** (build-time):
  - `cmake`, `clang`, `perl`, `pkg-config` — required to build the
    `aws-lc-rs` crypto backend.
  - `libpam0g-dev` (Debian/Ubuntu) / `pam-devel` (Fedora/RHEL) — PAM
    authentication back-end.
  - `pandoc` — regenerates the Markdown man-page mirror at build time
    (see below). Optional for a plain build, required by CI.

Debian/Ubuntu:

```sh
sudo apt-get install -y cmake clang perl pkg-config libpam0g-dev pandoc
```

Fedora/RHEL:

```sh
sudo dnf install -y cmake clang perl pkgconf-pkg-config pam-devel pandoc
```

Runtime (when running the binary, not building it) only needs
`ca-certificates` and the PAM runtime (`libpam0g` / `pam`).

## Build and test

```sh
cargo build              # debug build
cargo build --release    # optimised build -> target/release/hypershunt

cargo test               # unit tests (all offline, no network/services)
cargo clippy --all-targets
```

Run it against the sample config:

```sh
cargo run -- --config hypershunt.kdl
hypershunt --check-config --config hypershunt.kdl   # validate only
```

## Man page and its Markdown mirror

`docs/hypershunt.1` (troff) is the single source of truth for the
manual. `build.rs` regenerates `docs/manual.md` from it on every build
via `pandoc`, so the two never drift.

- With `pandoc` installed, editing `docs/hypershunt.1` and rebuilding
  updates `docs/manual.md` automatically — commit both.
- Without `pandoc`, the build still succeeds (it prints a warning and
  leaves the committed `docs/manual.md` in place).
- CI installs `pandoc` and fails if the committed `docs/manual.md` is
  out of date, so it can't go stale on `main`.

## Integration tests

The integration suite runs inside a container (it exercises real TLS,
HTTP/3, and reverse-proxy paths). It needs `podman`:

```sh
cargo install cargo-run-script        # one-time
cargo run-script smoke                # release build + build & run the
                                      # integration container
```

`smoke` also builds the `h3get` example (an HTTP/3 client the suite uses
because Debian's `curl` lacks `--http3`).

## Packaging

Install the packaging helpers once:

```sh
cargo install cargo-deb cargo-generate-rpm cargo-run-script
```

### Debian (`.deb`)

```sh
cargo deb            # builds release then packages
                     # -> target/debian/hypershunt_<version>_<arch>.deb
```

### RPM (`.rpm`)

```sh
cargo build --release        # cargo-generate-rpm packages an existing binary
cargo generate-rpm           # -> target/generate-rpm/hypershunt-<version>-1.<arch>.rpm
```

### OCI container image

Multi-stage build on `debian:trixie-slim`. Needs `podman`:

```sh
cargo run-script oci         # tags hypershunt:<version> and hypershunt:latest
```

or directly:

```sh
podman build -f packaging/oci/Containerfile -t hypershunt:latest .
podman run --rm -p 80:80 -p 443:443 hypershunt:latest
```

## Continuous integration

`.github/workflows/build.yml` runs on every push/PR to `main`: build,
unit tests, the man-page-mirror drift check, then the containerised
integration suite. `.github/workflows/release.yml` runs on `v*` tags to
build the OCI image and the `.deb`/`.rpm` artifacts and publish a
release.
