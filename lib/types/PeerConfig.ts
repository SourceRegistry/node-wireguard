import { Key } from './Key';
import { AllowedIP } from './AllowedIP';

/**
 * Peer configuration input for WireGuardClient.configureDevice() (mirrors
 * wgtypes.PeerConfig). Optional fields follow wgctrl-go's pointer semantics:
 * `undefined` = leave unchanged, a present value (including 0 / '') = apply it.
 */
export interface PeerConfig {
    /** Identifies which peer this entry applies to. Mandatory. */
    publicKey: Key;
    /** Remove this peer from the device's peer list. */
    remove?: boolean;
    /** Only apply this entry if the peer already exists on the device. */
    updateOnly?: boolean;
    /** undefined = unchanged; '' (all-zero key) clears the preshared key. */
    presharedKey?: Key;
    /** "host:port" / "[host]:port". */
    endpoint?: string;
    /** Seconds; undefined = unchanged, 0 = clears (disables keepalive). */
    persistentKeepaliveInterval?: number;
    /** Replace this peer's allowed-ips list instead of appending to it. */
    replaceAllowedIPs?: boolean;
    allowedIPs?: AllowedIP[];
}
