#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../../.."
npx tsc -p tsconfig.json
