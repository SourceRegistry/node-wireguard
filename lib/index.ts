/**
 * @author A.P.A. Slaa (a.p.a.slaa@projectsource.nl) ProjectSource V.O.F.
 */

import binding from './binding';
import { Device } from './types/Device';
import { Config } from './types/Config';

export * from './types';

interface NativeWireGuardClient {
    createDevice(name: string): Promise<void>;
    deleteDevice(name: string): Promise<void>;
    devices(): Promise<Device[]>;
    device(name: string): Promise<Device>;
    configureDevice(name: string, cfg: Config): Promise<void>;
    setUp(name: string): Promise<void>;
    setDown(name: string): Promise<void>;
    setAddress(name: string, cidr: string): Promise<void>;
    deleteAddress(name: string, cidr: string): Promise<void>;
    close(): void;
}

interface NativeBinding {
    WireGuardClient: new () => NativeWireGuardClient;
    generatePrivateKey(): string;
    generatePresharedKey(): string;
    publicKey(privateKey: string): string;
}

const native = binding as NativeBinding;

/**
 * Manages WireGuard interfaces and their peers via the kernel's "wireguard"
 * generic-netlink family - the same protocol wgctrl-go's Linux backend uses -
 * plus rtnetlink-based interface lifecycle (createDevice/deleteDevice), which
 * wgctrl-go itself does not provide.
 *
 * Linux only. Requires CAP_NET_ADMIN (typically: run as root).
 *
 * Calls on one instance are serialized (queued internally) since the
 * underlying netlink socket is not safe for overlapping use - issuing two
 * calls without awaiting the first no longer corrupts the socket, but they
 * still execute one at a time, in call order. Use separate WireGuardClient
 * instances if you actually want concurrent (parallel) netlink calls.
 */
export class WireGuardClient {
    private native: NativeWireGuardClient;
    private queue: Promise<void> = Promise.resolve();

    constructor() {
        this.native = new native.WireGuardClient();
    }

    // Chains `task` after every previously enqueued task, so only one native
    // call is ever in flight at a time. A rejected task must not break the
    // chain for tasks queued after it - only the caller of that task should
    // see the rejection.
    private enqueue<T>(task: () => Promise<T>): Promise<T> {
        const result = this.queue.then(task, task);
        this.queue = result.then(
            () => undefined,
            () => undefined,
        );
        return result;
    }

    /** Creates a new WireGuard-type network interface. Rejects with code 'EEXIST' if it already exists. */
    createDevice(name: string): Promise<void> {
        return this.enqueue(() => this.native.createDevice(name));
    }

    /** Deletes a WireGuard interface. Rejects with code 'ENODEV' if it doesn't exist. */
    deleteDevice(name: string): Promise<void> {
        return this.enqueue(() => this.native.deleteDevice(name));
    }

    /** Lists every WireGuard interface currently present on the system. */
    devices(): Promise<Device[]> {
        return this.enqueue(() => this.native.devices());
    }

    /** Fetches one WireGuard interface by name. Rejects with code 'ENODEV' if it's not a WireGuard interface. */
    device(name: string): Promise<Device> {
        return this.enqueue(() => this.native.device(name));
    }

    /** Applies a configuration to an existing WireGuard interface. See {@link Config} for field semantics. */
    configureDevice(name: string, cfg: Config): Promise<void> {
        return this.enqueue(() => this.native.configureDevice(name, cfg));
    }

    /** Brings the interface administratively up. Required for traffic to flow - createDevice() leaves it down. */
    setUp(name: string): Promise<void> {
        return this.enqueue(() => this.native.setUp(name));
    }

    /** Brings the interface administratively down. */
    setDown(name: string): Promise<void> {
        return this.enqueue(() => this.native.setDown(name));
    }

    /** Assigns a local address (e.g. "10.0.0.1/24") to the interface. Replaces any existing address with the same prefix. */
    setAddress(name: string, cidr: string): Promise<void> {
        return this.enqueue(() => this.native.setAddress(name, cidr));
    }

    /** Removes a previously assigned address. */
    deleteAddress(name: string, cidr: string): Promise<void> {
        return this.enqueue(() => this.native.deleteAddress(name, cidr));
    }

    /**
     * Releases the underlying netlink socket. The instance is unusable
     * afterwards. Does not wait for queued calls to finish - close() after
     * awaiting your last call, not concurrently with it.
     */
    close(): void {
        this.native.close();
    }
}

/** Generates a new Curve25519 private key, base64-encoded (same form as `wg genkey`). */
export function generatePrivateKey(): string {
    return native.generatePrivateKey();
}

/** Generates a new opaque preshared key, base64-encoded (same form as `wg genpsk`). */
export function generatePresharedKey(): string {
    return native.generatePresharedKey();
}

/** Derives the base64-encoded public key for a base64-encoded private key (same as `wg pubkey`). */
export function publicKey(privateKey: string): string {
    return native.publicKey(privateKey);
}
