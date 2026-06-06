#!/usr/bin/env bash
# Host-side driver for the container integration suite.
#
# This is the EXPENSIVE test path -- it is deliberately not part of
# `cargo test`.  It builds the release binary and the test-only example
# helpers, bakes them into the test image (tests/integration/Containerfile
# copies them in), then runs tests/integration/run.sh *inside* the
# container.  CI runs this exact script too, so there is one source of
# truth for the recipe.
#
# Requires: a Rust toolchain and podman (or set CONTAINER_ENGINE=docker).
#
#   ./tests/integration/smoke.sh
set -euo pipefail

# Run from the repo root regardless of the caller's cwd.
cd "$(dirname "$(readlink -f "$0")")/../.."

engine="${CONTAINER_ENGINE:-podman}"

# The Containerfile copies these pre-built artifacts; build them first.
# h3get is an HTTP/3 client (Debian curl lacks --http3); h2c_connect_echo
# is an h2 prior-knowledge CONNECT echo server for the upgrade-bridge suite.
cargo build --release
cargo build --release --example h3get
cargo build --release --example h2c_connect_echo

"$engine" build -f tests/integration/Containerfile -t hypershunt-test .
exec "$engine" run --rm hypershunt-test
