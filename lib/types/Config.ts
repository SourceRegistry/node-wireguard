import { Key } from './Key';
import { PeerConfig } from './PeerConfig';

/**
 * Device configuration input for WireGuardClient.configureDevice() (mirrors
 * wgtypes.Config). Optional fields follow wgctrl-go's pointer semantics:
 * `undefined` = leave unchanged, a present value (including 0 / '') = apply it.
 */
export interface Config {
    /** undefined = unchanged; '' (all-zero key) clears the private key. */
    privateKey?: Key;
    listenPort?: number;
    /** undefined = unchanged; 0 clears the firewall mark. */
    firewallMark?: number;
    /** Replace the device's entire peer list instead of merging into it. */
    replacePeers?: boolean;
    peers?: PeerConfig[];
}
