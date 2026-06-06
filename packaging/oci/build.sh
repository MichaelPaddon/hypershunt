#!/usr/bin/env bash
# Build the release OCI image from packaging/oci/Containerfile, tagged
# with the crate version and `latest`.  Local convenience only -- the
# release workflow builds (and pushes, multi-arch) the image itself.
#
# Requires: podman (or set CONTAINER_ENGINE=docker).
#
#   ./packaging/oci/build.sh
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")/../.."

engine="${CONTAINER_ENGINE:-podman}"
version=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)

exec "$engine" build -f packaging/oci/Containerfile \
    -t "hypershunt:$version" -t hypershunt:latest .
