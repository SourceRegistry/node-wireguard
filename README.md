# @sourceregistry/node-wireguard

[![npm version](https://img.shields.io/npm/v/@sourceregistry/node-wireguard.svg)](https://www.npmjs.com/package/@sourceregistry/node-wireguard)
[![npm downloads](https://img.shields.io/npm/dm/@sourceregistry/node-wireguard.svg)](https://www.npmjs.com/package/@sourceregistry/node-wireguard)
[![CI](https://github.com/SourceRegistry/node-wireguard/actions/workflows/ci.yml/badge.svg)](https://github.com/SourceRegistry/node-wireguard/actions/workflows/ci.yml)
[![node engine](https://img.shields.io/node/v/@sourceregistry/node-wireguard.svg)](package.json)
[![license](https://img.shields.io/npm/l/@sourceregistry/node-wireguard.svg)](LICENSE)

Native Node.js (N-API) addon for managing WireGuard interfaces and peers on Linux, with a TypeScript API on top. Talks directly to the kernel's `wireguard` generic-netlink family — the same wire protocol [wgctrl-go](https://github.com/WireGuard/wgctrl-go)'s Linux backend uses — plus rtnetlink for interface lifecycle. No shelling out to `wg`/`ip`.

Built for [WireGuard®](https://www.wireguard.com/), a registered trademark of Jason A. Donenfeld. This is an independent, unofficial project, not affiliated with or endorsed by the WireGuard project.

## Features

- **Full interface lifecycle** — `createDevice()` / `deleteDevice()` (rtnetlink `RTM_NEWLINK`/`RTM_DELLINK`, `IFLA_INFO_KIND=wireguard`). Goes beyond wgctrl-go, which assumes the link already exists.
- **Address + link state** — `setAddress()` / `deleteAddress()` (rtnetlink `RTM_NEWADDR`/`RTM_DELADDR`) and `setUp()` / `setDown()` (`RTM_NEWLINK` + `IFF_UP`). A freshly created device has no address and is down by default — these are what make it actually pass traffic.
- **Device + peer configuration** — `configureDevice()` sets private key, listen port, firewall mark, and peers (add/update/remove, allowed-IPs, preshared key, endpoint, persistent keepalive). Mirrors wgtypes' "pointer-optional" semantics: omit a field to leave it unchanged, set it (even to `0`/`''`) to apply/clear it explicitly.
- **Device + peer inspection** — `devices()` / `device(name)` return live status: peers, handshake times, rx/tx byte counters, allowed-IPs.
- **Userspace (UAPI) backend fallback** — `devices()`/`device()`/`configureDevice()` automatically use the cross-platform UAPI socket (`/var/run/wireguard/<name>.sock`) for interfaces backed by a userspace implementation like `wireguard-go`, instead of kernel netlink, transparently (`device.type` reports which). Interface lifecycle (`createDevice`/`setUp`/`setAddress`/etc.) is unaffected - those are still plain rtnetlink and work the same either way, since wireguard-go creates a real kernel-visible TUN interface.
- **Key utilities** — `generatePrivateKey()`, `generatePresharedKey()`, `publicKey()` via libsodium X25519, matching `wg genkey`/`wg genpsk`/`wg pubkey` output (base64, 32 bytes).
- All blocking netlink syscalls run off the JS thread via `Napi::AsyncWorker` — every `WireGuardClient` method returns a `Promise`.

## Requirements

- Linux with the WireGuard kernel module/support loaded (`modprobe wireguard` or built-in).
- `CAP_NET_ADMIN` (typically: run as root) for `createDevice`/`deleteDevice`/`configureDevice`.
- Build deps: `libmnl-dev`, `libsodium-dev`, `pkg-config`, a C++17 toolchain.

## Install

```sh
npm install
npm run build
```

Or use the bundled `.devcontainer` (works on Windows too, via Docker Desktop/WSL2) — see below.

## Usage

```ts
import { WireGuardClient, generatePrivateKey, publicKey } from '@sourceregistry/node-wireguard';

const client = new WireGuardClient();

await client.createDevice('wg0');

const privateKey = generatePrivateKey();
await client.configureDevice('wg0', { privateKey, listenPort: 51820 });

await client.setAddress('wg0', '10.0.0.1/24');
await client.setUp('wg0');

await client.configureDevice('wg0', {
  peers: [{
    publicKey: '<peer-public-key>',
    endpoint: '203.0.113.5:51820',
    persistentKeepaliveInterval: 25,
    allowedIPs: ['10.0.0.2/32'],
  }],
});

const device = await client.device('wg0');
console.log(device.publicKey, device.peers);

client.close();
```

More examples in [`examples/`](./examples): `list-devices`, `get-device`, `generate-keypair`, `create-interface`, `add-peer`, `remove-peer`.

## Caveats

- Linux only (the UAPI backend means a wireguard-go *peer* anywhere works fine, but this addon itself only runs on Linux).
- UAPI socket lookup only checks `/var/run/wireguard/<name>.sock` - not `$XDG_RUNTIME_DIR/wireguard/` (which wgctrl-go's wguser backend also checks).
- Route management (beyond the implicit route rtnetlink installs for an assigned address's own subnet) is left to the caller — use `ip route` or rtnetlink directly for anything beyond that.
- Calls on one `WireGuardClient` instance are serialized internally (queued, run one at a time in call order) — issuing several without awaiting each is safe but not parallel. Use separate instances if you want calls to actually run concurrently.

## Development

```sh
npm run build:cpp   # node-gyp rebuild
npm run build:ts    # tsc
npm test            # node:test; kernel/UAPI-backed tests auto-skip unless root + the relevant backend is present
```

A `.devcontainer` is included (Dockerfile + `devcontainer.json`, `capAdd: NET_ADMIN`) so the addon builds and the full test suite — including real interface create/configure/delete — runs the same way on Windows (via Docker Desktop/WSL2) as on Linux.

## Packaging / CI

`npm run package` (`scripts/package/package.sh`) builds the addon and stages the compiled `.node` into `bin/<arch-triplet>/` (currently `x86_64-linux-gnu`, `aarch64-linux-gnu`), where `lib/binding.ts` looks for a prebuild when installed from npm. If no matching prebuild is present (e.g. an unpublished triplet), `npm install`'s `gypfile`-triggered `node-gyp rebuild` compiles it locally instead, and the loader falls back to that build automatically.

`.github/workflows/ci.yml` runs on push/PR: installs native deps (`libmnl-dev`/`libsodium-dev`), builds, typechecks, and runs the test suite as root with `modprobe wireguard` best-effort (kernel-backed tests self-skip if the module isn't available on the runner) - plus a separate job that stages a prebuild and runs `npm pack --dry-run` to catch packaging regressions.

## Releasing

Releases are automated with [semantic-release](https://semantic-release.gitbook.io/) off [Conventional Commits](https://www.conventionalcommits.org/) (`fix:`, `feat:`, `feat!:`/`BREAKING CHANGE:`, etc.) - on every push to `main` (stable) or `alpha` (prerelease) that passes CI, the `release` job:

1. Determines the next version from commit messages since the last release.
2. Builds the addon and runs `prepublishOnly` (`npm run package`) to stage the `bin/<triplet>/` prebuild into the tarball.
3. Publishes to npm and pushes a GitHub release + tag + `CHANGELOG.md` update.

Requires repo secrets `NPM_TOKEN` (npm publish) and the default `GITHUB_TOKEN` (release/tag/changelog commit). Only the runner's own architecture (`x86_64-linux-gnu` on GitHub-hosted `ubuntu-latest`) gets a prebuild this way - other architectures fall back to compiling from source on `npm install` (see Packaging above).

## License

Apache-2.0
