import * as assert from 'node:assert';
import * as fs from 'node:fs';
import { execFileSync, spawn, ChildProcess } from 'node:child_process';
import { describe, it, beforeEach, afterEach } from 'node:test';
import { generatePrivateKey, generatePresharedKey, publicKey, WireGuardClient } from '../lib';

describe('keys', () => {
    it('generates a base64-encoded 32-byte private key', () => {
        const key = generatePrivateKey();
        assert.strictEqual(Buffer.from(key, 'base64').length, 32);
    });

    it('generates a base64-encoded 32-byte preshared key', () => {
        const key = generatePresharedKey();
        assert.strictEqual(Buffer.from(key, 'base64').length, 32);
    });

    it('derives the same public key twice for the same private key', () => {
        const priv = generatePrivateKey();
        assert.strictEqual(publicKey(priv), publicKey(priv));
    });

    it('derives different public keys for different private keys', () => {
        assert.notStrictEqual(publicKey(generatePrivateKey()), publicKey(generatePrivateKey()));
    });
});

const canTestKernel = process.platform === 'linux' && process.getuid?.() === 0 && fs.existsSync('/sys/module/wireguard');

(canTestKernel ? describe : describe.skip)('WireGuardClient (requires root + wireguard kernel module)', () => {
    const ifaceName = 'wg-node-test';
    let client: WireGuardClient;

    beforeEach(() => {
        client = new WireGuardClient();
    });

    afterEach(async () => {
        try {
            await client.deleteDevice(ifaceName);
        } catch {
            // already gone
        }
        client.close();
    });

    it('creates, configures, and deletes an interface', async () => {
        await client.createDevice(ifaceName);

        const privateKey = generatePrivateKey();
        await client.configureDevice(ifaceName, { privateKey, listenPort: 51820 });

        const device = await client.device(ifaceName);
        assert.strictEqual(device.name, ifaceName);
        assert.strictEqual(device.listenPort, 51820);
        assert.strictEqual(device.publicKey, publicKey(privateKey));

        await client.deleteDevice(ifaceName);
        await assert.rejects(() => client.device(ifaceName), (err: any) => err.code === 'ENODEV');
    });

    it('adds and removes a peer', async () => {
        await client.createDevice(ifaceName);
        await client.configureDevice(ifaceName, { privateKey: generatePrivateKey() });

        const peerKey = publicKey(generatePrivateKey());
        await client.configureDevice(ifaceName, {
            peers: [{ publicKey: peerKey, allowedIPs: ['10.0.0.2/32'] }],
        });

        let device = await client.device(ifaceName);
        assert.strictEqual(device.peers.length, 1);
        assert.strictEqual(device.peers[0].publicKey, peerKey);

        await client.configureDevice(ifaceName, {
            peers: [{ publicKey: peerKey, remove: true }],
        });

        device = await client.device(ifaceName);
        assert.strictEqual(device.peers.length, 0);
    });

    it('assigns an address and brings the interface up', async () => {
        await client.createDevice(ifaceName);
        await client.configureDevice(ifaceName, { privateKey: generatePrivateKey() });

        await client.setAddress(ifaceName, '10.0.0.1/24');
        await client.setUp(ifaceName);

        const flags = fs.readFileSync(`/sys/class/net/${ifaceName}/flags`, 'utf8').trim();
        assert.strictEqual(parseInt(flags, 16) & 0x1, 0x1); // IFF_UP

        await client.setDown(ifaceName);
        await client.deleteAddress(ifaceName, '10.0.0.1/24');
    });

    it('merges one peer\'s allowed-ips when the kernel splits its dump across multiple messages', async () => {
        await client.createDevice(ifaceName);
        await client.configureDevice(ifaceName, { privateKey: generatePrivateKey() });

        const peerKey = publicKey(generatePrivateKey());
        // Enough /32s to force the kernel to split this one peer's dump across
        // multiple WGPEER_A_PEERS entries / netlink messages.
        const allowedIPs = Array.from({ length: 400 }, (_, i) => `10.${(i >> 8) & 0xff}.${i & 0xff}.1/32`);
        await client.configureDevice(ifaceName, {
            peers: [{ publicKey: peerKey, allowedIPs }],
        });

        const device = await client.device(ifaceName);
        assert.strictEqual(device.peers.length, 1, 'continuation entries should merge into one peer, not duplicate');
        assert.strictEqual(device.peers[0].allowedIPs.length, allowedIPs.length);
    });

    it('rejects out-of-range CIDR masks instead of silently truncating them', async () => {
        await client.createDevice(ifaceName);
        await client.configureDevice(ifaceName, { privateKey: generatePrivateKey() });
        const peerKey = publicKey(generatePrivateKey());

        await assert.rejects(() =>
            client.configureDevice(ifaceName, { peers: [{ publicKey: peerKey, allowedIPs: ['10.0.0.0/33'] }] }),
        );
        await assert.rejects(() =>
            client.configureDevice(ifaceName, { peers: [{ publicKey: peerKey, allowedIPs: ['fd00::/129'] }] }),
        );
        await assert.rejects(() =>
            client.configureDevice(ifaceName, { peers: [{ publicKey: peerKey, allowedIPs: ['10.0.0.0/-1'] }] }),
        );
        await assert.rejects(() =>
            client.configureDevice(ifaceName, { peers: [{ publicKey: peerKey, allowedIPs: ['10.0.0.0/24abc'] }] }),
        );

        const device = await client.device(ifaceName);
        assert.strictEqual(device.peers.length, 0, 'no peer should have been added by the rejected calls');
    });

    it('serializes overlapping calls instead of racing the shared netlink socket', async () => {
        await client.createDevice(ifaceName);
        await client.configureDevice(ifaceName, { privateKey: generatePrivateKey() });

        const peerKeys = Array.from({ length: 20 }, () => publicKey(generatePrivateKey()));
        // Fire all 20 configureDevice calls without awaiting each individually -
        // if calls weren't serialized, concurrent use of the netlink socket
        // would corrupt requests/replies and this would fail or hang.
        await Promise.all(
            peerKeys.map((publicKeyStr) =>
                client.configureDevice(ifaceName, { peers: [{ publicKey: publicKeyStr, allowedIPs: [] }] }),
            ),
        );

        const device = await client.device(ifaceName);
        const gotKeys = new Set(device.peers.map((p) => p.publicKey));
        assert.strictEqual(device.peers.length, peerKeys.length);
        for (const key of peerKeys) {
            assert.ok(gotKeys.has(key), `missing peer ${key}`);
        }
    });
});

function findUapiBinary(): string | undefined {
    for (const name of ['wireguard-go', 'wireguard']) {
        try {
            return execFileSync('which', [name], { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
        } catch {
            // not found, try next
        }
    }
    return undefined;
}

const uapiBinary = process.platform === 'linux' && process.getuid?.() === 0 ? findUapiBinary() : undefined;

(uapiBinary ? describe : describe.skip)('WireGuardClient UAPI backend (requires root + wireguard-go binary)', () => {
    const ifaceName = 'wg-uapi-test'; // must stay <= 15 chars (IFNAMSIZ-1) or TUN creation fails with EINVAL
    const socketPath = `/var/run/wireguard/${ifaceName}.sock`;
    let client: WireGuardClient;
    let daemon: ChildProcess;

    beforeEach(async () => {
        fs.mkdirSync('/var/run/wireguard', { recursive: true });
        daemon = spawn(uapiBinary as string, ['-f', ifaceName], { stdio: 'ignore' });
        for (let i = 0; i < 50 && !fs.existsSync(socketPath); i++) {
            await new Promise((r) => setTimeout(r, 100));
        }
        if (!fs.existsSync(socketPath)) {
            throw new Error(`${uapiBinary} did not create ${socketPath} in time`);
        }
        client = new WireGuardClient();
    }, { timeout: 10000 }); // spawning the daemon and waiting for its socket can exceed node:test's 1s default

    afterEach(() => {
        client?.close();
        daemon?.kill();
    });

    it('reports type "userspace" and round-trips device + peer config over the UAPI socket', async () => {
        const privateKey = generatePrivateKey();
        await client.configureDevice(ifaceName, { privateKey, listenPort: 51821 });

        const device = await client.device(ifaceName);
        assert.strictEqual(device.type, 'userspace');
        assert.strictEqual(device.listenPort, 51821);
        assert.strictEqual(device.publicKey, publicKey(privateKey));

        const peerKey = publicKey(generatePrivateKey());
        await client.configureDevice(ifaceName, {
            peers: [{ publicKey: peerKey, allowedIPs: ['10.9.0.2/32'], persistentKeepaliveInterval: 25 }],
        });

        const device2 = await client.device(ifaceName);
        assert.strictEqual(device2.peers.length, 1);
        assert.strictEqual(device2.peers[0].publicKey, peerKey);
        assert.deepStrictEqual(device2.peers[0].allowedIPs, ['10.9.0.2/32']);

        const devices = await client.devices();
        assert.ok(devices.some((d) => d.name === ifaceName && d.type === 'userspace'));

        await client.configureDevice(ifaceName, { peers: [{ publicKey: peerKey, remove: true }] });
        const device3 = await client.device(ifaceName);
        assert.strictEqual(device3.peers.length, 0);
    });
});
