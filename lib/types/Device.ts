import { Key } from './Key';
import { Peer } from './Peer';

/**
 * Backend that produced this Device: 'linux-kernel' for the kernel module
 * (genetlink), 'userspace' for a UAPI-socket-backed implementation like
 * wireguard-go (e.g. /var/run/wireguard/<name>.sock).
 */
export type DeviceType = 'linux-kernel' | 'userspace';

/**
 * Read-only snapshot of a WireGuard interface, as returned by
 * WireGuardClient.device()/devices() (mirrors wgtypes.Device).
 */
export interface Device {
    name: string;
    type: DeviceType;
    /** Empty string if no private key is set. */
    privateKey: Key;
    /** Empty string if no private key is set (no public key can be derived). */
    publicKey: Key;
    listenPort: number;
    firewallMark: number;
    peers: Peer[];
}
