import { WireGuardClient } from '../../lib';

const ifaceName = process.argv[2] ?? 'wg-test';

async function main() {
    const client = new WireGuardClient();
    try {
        const device = await client.device(ifaceName);
        // JSON.stringify can't serialize BigInt (receiveBytes/transmitBytes) directly.
        console.log(JSON.stringify(device, (_key, value) => (typeof value === 'bigint' ? value.toString() : value), 2));
    } finally {
        client.close();
    }
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
