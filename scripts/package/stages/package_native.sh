#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../../.."

case "$(uname -m)" in
    x86_64) triplet="x86_64-linux-gnu" ;;
    aarch64) triplet="aarch64-linux-gnu" ;;
    *)
        echo "package_native.sh: unsupported architecture $(uname -m) (only x86_64/aarch64 prebuilds are supported)" >&2
        exit 1
        ;;
esac

src="build/Release/node-wireguard.node"
if [ ! -f "$src" ]; then
    echo "package_native.sh: $src not found - run \`npm run build:cpp\` first" >&2
    exit 1
fi

dest_dir="bin/$triplet"
mkdir -p "$dest_dir"
cp "$src" "$dest_dir/node-wireguard.node"
echo "packaged $src -> $dest_dir/node-wireguard.node"
