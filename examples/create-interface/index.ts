import { WireGuardClient, generatePrivateKey } from '../../lib';

const ifaceName = process.argv[2] ?? 'wg-test';

async function main() {
    const client = new WireGuardClient();
    try {
        await client.createDevice(ifaceName);
        const privateKey = generatePrivateKey();

        await client.configureDevice(ifaceName, {
            privateKey,
            listenPort: 51820,
        });

        // Without an address + up, the interface exists but can't pass traffic.
        await client.setAddress(ifaceName, '10.0.0.1/24');
        await client.setUp(ifaceName);

        const device = await client.device(ifaceName);
        console.log(`created ${ifaceName}, public key: ${device.publicKey}`);
    } finally {
        client.close();
    }
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
