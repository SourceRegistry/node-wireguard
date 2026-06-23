#!/usr/bin/env bash
set -euo pipefail

# Installs the native build dependencies for node-wireguard.
# Requires: a Linux host with apt (Debian/Ubuntu). For other distros, install
# the equivalent of libmnl-dev + libsodium-dev (+ pkg-config, build-essential)
# via your package manager.

sudo apt-get update
sudo apt-get install -y \
    build-essential \
    pkg-config \
    libmnl-dev \
    libsodium-dev

if [ ! -d /sys/module/wireguard ]; then
    echo "warning: wireguard kernel module is not currently loaded (modprobe wireguard)" >&2
    echo "         the addon will still build, but kernel-backed calls will fail with ENODEV until it is" >&2
fi
