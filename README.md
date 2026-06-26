# @sourceregistry/node-wireguard

[![npm version](https://img.shields.io/npm/v/@sourceregistry/node-wireguard.svg)](https://www.npmjs.com/package/@sourceregistry/node-wireguard)
[![npm downloads](https://img.shields.io/npm/dm/@sourceregistry/node-wireguard.svg)](https://www.npmjs.com/package/@sourceregistry/node-wireguard)
[![CI](https://github.com/SourceRegistry/node-wireguard/actions/workflows/ci.yml/badge.svg)](https://github.com/SourceRegistry/node-wireguard/actions/workflows/ci.yml)
[![node engine](https://img.shields.io/node/v/@sourceregistry/node-wireguard.svg)](package.json)
[![license](https://img.shields.io/npm/l/@sourceregistry/node-wireguard.svg)](LICENSE)

Native Node.js addon for managing WireGuard interfaces and peers on Linux, with TypeScript types included. It talks directly to the kernel and to WireGuard userspace control sockets; it does not shell out to `wg` or `ip`.

Built for [WireGuard](https://www.wireguard.com/), a registered trademark of Jason A. Donenfeld. This is an independent, unofficial project, not affiliated with or endorsed by the WireGuard project.

## Features

- **Full interface lifecycle:** `createDevice()` / `deleteDevice()` (rtnetlink `RTM_NEWLINK`/`RTM_DELLINK`, `IFLA_INFO_KIND=wireguard`). Goes beyond wgctrl-go, which assumes the link already exists.
- **Address + link state:** `setAddress()` / `deleteAddress()` (rtnetlink `RTM_NEWADDR`/`RTM_DELADDR`) and `setUp()` / `setDown()` (`RTM_NEWLINK` + `IFF_UP`). A freshly created device has no address and is down by default. These are what make it actually pass traffic.
- **Device + peer configuration:** `configureDevice()` sets private key, listen port, firewall mark, and peers (add/update/remove, allowed-IPs, preshared key, endpoint, persistent keepalive). Mirrors wgtypes' "pointer-optional" semantics: omit a field to leave it unchanged, set it (even to `0`/`''`) to apply/clear it explicitly.
- **Device + peer inspection:** `devices()` / `device(name)` return live status: peers, handshake times, rx/tx byte counters, allowed-IPs.
- **Userspace (UAPI) backend fallback:** `devices()`/`device()`/`configureDevice()` automatically use the cross-platform UAPI socket (`/var/run/wireguard/<name>.sock`) for interfaces backed by a userspace implementation like `wireguard-go`, instead of kernel netlink, transparently (`device.type` reports which). Interface lifecycle (`createDevice`/`setUp`/`setAddress`/etc.) is unaffected - those are still plain rtnetlink and work the same either way, since wireguard-go creates a real kernel-visible TUN interface.
- **Key utilities:** `generatePrivateKey()`, `generatePresharedKey()`, `publicKey()` via OpenSSL X25519, matching `wg genkey`/`wg genpsk`/`wg pubkey` output (base64, 32 bytes).
- All blocking netlink syscalls run off the JS thread via `Napi::AsyncWorker`; every `WireGuardClient` method returns a `Promise`.

## Requirements

- Linux with the WireGuard kernel module/support loaded (`modprobe wireguard` or built-in).
- Node.js 22 or newer.
- `CAP_NET_ADMIN` (typically: run as root) for `createDevice`/`deleteDevice`/`configureDevice`.
- Runtime libraries: `libmnl` and OpenSSL `libcrypto`.

On Debian/Ubuntu, the runtime libraries are:

```sh
sudo apt-get install -y libmnl0 libssl3
```

If your platform does not have a prebuilt addon available, build the native addon from source after installing. In that case you also need:

```sh
sudo apt-get install -y build-essential pkg-config libmnl-dev libssl-dev
```

## Install

```sh
npm install @sourceregistry/node-wireguard
```

If a matching prebuild is available, install is quick and does not need a compiler. If not, run `npm rebuild @sourceregistry/node-wireguard` after installing with the build dependencies above available.

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

- Linux only. You can connect to peers on any WireGuard implementation, but this addon itself runs on Linux.
- UAPI socket lookup only checks `/var/run/wireguard/<name>.sock` - not `$XDG_RUNTIME_DIR/wireguard/` (which wgctrl-go's wguser backend also checks).
- Route management (beyond the implicit route rtnetlink installs for an assigned address's own subnet) is left to the caller. Use `ip route` or rtnetlink directly for anything beyond that.
- Calls on one `WireGuardClient` instance are serialized internally (queued, run one at a time in call order). Issuing several without awaiting each is safe but not parallel. Use separate instances if you want calls to actually run concurrently.

## Development

Clone the repository, install dependencies, then build:

```sh
npm install
npm run build
```

Useful commands:

```sh
npm run build:cpp   # node-gyp rebuild
npm run build:ts    # tsc
npm test            # node:test; kernel/UAPI-backed tests auto-skip unless root + the relevant backend is present
```

A `.devcontainer` is included (Dockerfile + `devcontainer.json`, `capAdd: NET_ADMIN`) so the addon builds and the full test suite, including real interface create/configure/delete, runs the same way on Windows (via Docker Desktop/WSL2) as on Linux.

## Prebuilds

Published packages may include native prebuilds in `bin/<arch-triplet>/`. When no matching prebuild exists for your system, rebuild the package locally with `npm rebuild @sourceregistry/node-wireguard`.

Maintainers can run `npm run package` to stage a local prebuild before packing or publishing.

## FAQ

### Do I need to allow npm install scripts?

No. The published package does not use an npm `install` lifecycle script, so package managers that warn about allowing scripts should not need any special approval for this package.

Runtime libraries are checked when the package is loaded. If `libmnl` or OpenSSL `libcrypto` is missing, `require('@sourceregistry/node-wireguard')` will throw an error with the package names to install.

If there is no prebuild for your platform, install the build dependencies and run `npm rebuild @sourceregistry/node-wireguard`.

## License

Apache-2.0
