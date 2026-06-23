#!/usr/bin/env bash
set -euo pipefail

# Builds the native addon + TS output, then stages the compiled .node into
# bin/<arch-triplet>/ the way lib/binding.ts expects to find it when this
# package is installed from npm (see the `is_package` branch there).
dir="$(dirname "$0")"
root="$dir/../.."

bash "$root/scripts/build/build.sh"
bash "$dir/stages/package_native.sh"

echo "package.sh: done. Run \`npm pack --dry-run\` to inspect what would be published."
