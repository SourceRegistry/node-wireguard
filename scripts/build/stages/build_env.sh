#!/usr/bin/env bash
set -euo pipefail

# Sanity-checks the build environment before compiling.

command -v node-gyp >/dev/null || { echo "node-gyp not found (npm install)" >&2; exit 1; }
command -v pkg-config >/dev/null || { echo "pkg-config not found (see scripts/setup/setup.sh)" >&2; exit 1; }
pkg-config --exists libmnl || { echo "libmnl-dev not found (see scripts/setup/setup.sh)" >&2; exit 1; }
pkg-config --exists libsodium || { echo "libsodium-dev not found (see scripts/setup/setup.sh)" >&2; exit 1; }
