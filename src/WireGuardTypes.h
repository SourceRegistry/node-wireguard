#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace wg {

constexpr size_t kKeyLen = 32;
using Key = std::array<uint8_t, kKeyLen>;

struct AllowedIP {
    std::string ip;   // textual IPv4/IPv6 address
    uint8_t family;   // AF_INET or AF_INET6
    uint8_t cidr;
};

// Read-only peer status, as returned by WG_CMD_GET_DEVICE (mirrors wgtypes.Peer).
struct Peer {
    Key publicKey{};
    std::optional<Key> presharedKey;
    std::optional<std::string> endpoint; // "host:port"
    uint16_t persistentKeepaliveInterval = 0; // seconds
    int64_t lastHandshakeTimeSec = 0;         // unix seconds, 0 = never
    uint64_t receiveBytes = 0;
    uint64_t transmitBytes = 0;
    std::vector<AllowedIP> allowedIPs;
    uint32_t protocolVersion = 0;
};

// Read-only device snapshot, as returned by WG_CMD_GET_DEVICE or the UAPI
// `get=1` request (mirrors wgtypes.Device, plus `userspace` to record which
// backend produced it - see DeviceToJs in WireGuardClient.cpp).
struct Device {
    std::string name;
    bool userspace = false; // true if fetched via the UAPI socket backend, not kernel netlink
    std::optional<Key> privateKey;
    std::optional<Key> publicKey;
    uint16_t listenPort = 0;
    uint32_t firewallMark = 0;
    std::vector<Peer> peers;
};

// Peer configuration input for WG_CMD_SET_DEVICE (mirrors wgtypes.PeerConfig).
// optional<T> absent == "leave unchanged"; present (even zero-valued) == "apply this value".
struct PeerConfig {
    Key publicKey{};
    bool remove = false;
    bool updateOnly = false;
    std::optional<Key> presharedKey;
    std::optional<std::string> endpoint; // "host:port"
    std::optional<uint16_t> persistentKeepaliveInterval; // seconds; 0 clears
    bool replaceAllowedIPs = false;
    std::vector<AllowedIP> allowedIPs;
};

// Device configuration input for WG_CMD_SET_DEVICE (mirrors wgtypes.Config).
struct Config {
    std::optional<Key> privateKey; // all-zero key clears the private key
    std::optional<uint16_t> listenPort;
    std::optional<uint32_t> firewallMark; // 0 clears
    bool replacePeers = false;
    std::vector<PeerConfig> peers;
};

} // namespace wg
