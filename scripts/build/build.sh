#!/usr/bin/env bash
set -euo pipefail

dir="$(dirname "$0")"
"$dir/stages/build_env.sh"
"$dir/stages/build_cpp.sh"
"$dir/stages/build_ts.sh"
