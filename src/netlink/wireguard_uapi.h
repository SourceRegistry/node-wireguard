#pragma once

// Mirrors the stable kernel UAPI <linux/wireguard.h> generic-netlink protocol
// (the same wire format wgctrl-go's wglinux backend speaks). Defined locally
// instead of #include <linux/wireguard.h> so the build doesn't depend on the
// build host having a sufficiently new kernel-headers package installed —
// these attribute IDs are part of WireGuard's stable ABI and do not change.

#define WG_GENL_NAME "wireguard"
#define WG_GENL_VERSION 1
#define WG_MULTICAST_GROUP_PEERS "peers"
#define WG_KEY_LEN 32

enum wg_cmd {
    WG_CMD_GET_DEVICE,
    WG_CMD_SET_DEVICE,
    __WG_CMD_MAX
};
#define WG_CMD_MAX (__WG_CMD_MAX - 1)

enum wgdevice_flag {
    WGDEVICE_F_REPLACE_PEERS = 1U << 0,
};

enum wgdevice_attribute {
    WGDEVICE_A_UNSPEC,
    WGDEVICE_A_IFINDEX,     // NLA_U32
    WGDEVICE_A_IFNAME,      // NLA_NUL_STRING, IFNAMSIZ - 1
    WGDEVICE_A_PRIVATE_KEY, // NLA_EXACT_LEN, WG_KEY_LEN
    WGDEVICE_A_PUBLIC_KEY,  // NLA_EXACT_LEN, WG_KEY_LEN
    WGDEVICE_A_FLAGS,       // NLA_U32
    WGDEVICE_A_LISTEN_PORT, // NLA_U16
    WGDEVICE_A_FWMARK,      // NLA_U32
    WGDEVICE_A_PEERS,       // NLA_NESTED
    __WGDEVICE_A_LAST
};
#define WGDEVICE_A_MAX (__WGDEVICE_A_LAST - 1)

enum wgpeer_flag {
    WGPEER_F_REMOVE_ME = 1U << 0,
    WGPEER_F_REPLACE_ALLOWEDIPS = 1U << 1,
    WGPEER_F_UPDATE_ONLY = 1U << 2,
};

enum wgpeer_attribute {
    WGPEER_A_UNSPEC,
    WGPEER_A_PUBLIC_KEY,                    // NLA_EXACT_LEN, WG_KEY_LEN
    WGPEER_A_PRESHARED_KEY,                 // NLA_EXACT_LEN, WG_KEY_LEN
    WGPEER_A_FLAGS,                         // NLA_U32
    WGPEER_A_ENDPOINT,                      // NLA_MIN_LEN(sockaddr), sockaddr_in/in6
    WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, // NLA_U16
    WGPEER_A_LAST_HANDSHAKE_TIME,           // NLA_EXACT_LEN, __kernel_timespec
    WGPEER_A_RX_BYTES,                      // NLA_U64
    WGPEER_A_TX_BYTES,                      // NLA_U64
    WGPEER_A_ALLOWEDIPS,                    // NLA_NESTED
    WGPEER_A_PROTOCOL_VERSION,              // NLA_U32
    __WGPEER_A_LAST
};
#define WGPEER_A_MAX (__WGPEER_A_LAST - 1)

enum wgallowedip_attribute {
    WGALLOWEDIP_A_UNSPEC,
    WGALLOWEDIP_A_FAMILY,    // NLA_U16, AF_INET or AF_INET6
    WGALLOWEDIP_A_IPADDR,    // NLA_MIN_LEN(4), 4 or 16 bytes
    WGALLOWEDIP_A_CIDR_MASK, // NLA_U8
    __WGALLOWEDIP_A_LAST
};
#define WGALLOWEDIP_A_MAX (__WGALLOWEDIP_A_LAST - 1)
