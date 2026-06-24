#!/usr/bin/env node
"use strict";

// Runs as this package's "install" lifecycle script (see package.json —
// "gypfile" is deliberately false so npm never auto-triggers node-gyp on its
// own). If a prebuild matching this platform/arch is already staged in
// bin/<triplet>/ (true for any npm-installed copy on a supported platform —
// see scripts/package/package.sh), there is nothing to build: skip straight
// to exit 0. Only platforms without a published prebuild fall through to an
// actual native build, which is the only case that needs a C++ toolchain,
// pkg-config, libmnl-dev, and libsodium-dev installed.

const { existsSync } = require("node:fs");
const { join } = require("node:path");
const { execFileSync } = require("node:child_process");

const ARCH_TO_TRIPLET = {
  x64: "x86_64-linux-gnu",
  arm64: "aarch64-linux-gnu",
};

const triplet = process.platform === "linux" ? ARCH_TO_TRIPLET[process.arch] : undefined;
const prebuildPath = triplet ? join(__dirname, "..", "bin", triplet, "node-wireguard.node") : undefined;

if (prebuildPath && existsSync(prebuildPath)) {
  console.log(`node-wireguard: using the bundled prebuild for ${triplet} — skipping the native build.`);
  process.exit(0);
}

console.log(
  `node-wireguard: no bundled prebuild for platform=${process.platform} arch=${process.arch} — building from ` +
    "source (requires a C++17 toolchain, pkg-config, libmnl-dev, libsodium-dev).",
);

execFileSync(process.execPath, [require.resolve("node-gyp/bin/node-gyp.js"), "rebuild"], { stdio: "inherit" });
