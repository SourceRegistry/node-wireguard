import { WireGuardClient } from '../../lib';

const ifaceName = process.argv[2] ?? 'wg-test';
const peerPublicKey = process.argv[3];

if (!peerPublicKey) {
    console.error('usage: remove-peer <iface> <peer-public-key>');
    process.exit(1);
}

async function main() {
    const client = new WireGuardClient();
    try {
        await client.configureDevice(ifaceName, {
            peers: [{ publicKey: peerPublicKey, remove: true }],
        });
        console.log(`removed peer ${peerPublicKey} from ${ifaceName}`);
    } finally {
        client.close();
    }
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
