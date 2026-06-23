#!/usr/bin/env bash
set -euo pipefail

dir="$(dirname "$0")"
bash "$dir/stages/build_env.sh"
bash "$dir/stages/build_cpp.sh"
bash "$dir/stages/build_ts.sh"
