import { Key } from './Key';
import { AllowedIP } from './AllowedIP';

/**
 * Read-only status of one configured peer, as returned by
 * WireGuardClient.device()/devices() (mirrors wgtypes.Peer).
 */
export interface Peer {
    publicKey: Key;
    /** Empty string if no preshared key is configured. */
    presharedKey: Key;
    /** "host:port" (IPv6 as "[host]:port"), or undefined if never connected. */
    endpoint?: string;
    /** Seconds; 0 = disabled. */
    persistentKeepaliveInterval: number;
    /** null if no handshake has occurred yet. */
    lastHandshakeTime: Date | null;
    receiveBytes: bigint;
    transmitBytes: bigint;
    allowedIPs: AllowedIP[];
    /** 0 = most recent WireGuard protocol version. */
    protocolVersion: number;
}
