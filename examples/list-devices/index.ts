import { WireGuardClient } from '../../lib';

async function main() {
    const client = new WireGuardClient();
    try {
        const devices = await client.devices();
        // JSON.stringify can't serialize BigInt (receiveBytes/transmitBytes) directly.
        console.log(JSON.stringify(devices, (_key, value) => (typeof value === 'bigint' ? value.toString() : value), 2));
    } finally {
        client.close();
    }
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
