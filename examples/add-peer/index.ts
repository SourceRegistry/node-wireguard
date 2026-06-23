import { WireGuardClient } from '../../lib';

const ifaceName = process.argv[2] ?? 'wg-test';
const peerPublicKey = process.argv[3];

if (!peerPublicKey) {
    console.error('usage: add-peer <iface> <peer-public-key>');
    process.exit(1);
}

async function main() {
    const client = new WireGuardClient();
    try {
        await client.configureDevice(ifaceName, {
            // replacePeers: false (default) - appends/updates this one peer, leaves others untouched
            peers: [
                {
                    publicKey: peerPublicKey,
                    endpoint: '203.0.113.5:51820',
                    persistentKeepaliveInterval: 25,
                    allowedIPs: ['10.0.0.2/32'],
                },
            ],
        });
        console.log(`added peer ${peerPublicKey} to ${ifaceName}`);
    } finally {
        client.close();
    }
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
