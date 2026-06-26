#include "NlAttr.h"
#include "../helpers/AsyncPromise.h"
#include "../helpers/IfName.h"
#include "wireguard_uapi.h"

#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <stdexcept>
#include <sys/socket.h>

extern "C" {
#include <linux/genetlink.h>
}

namespace netlink {

namespace {

// Strict decimal port parser: rejects empty input, leading/trailing garbage
// (e.g. "51820abc" or " 51820"), and anything outside 0..65535 - std::stoi
// alone accepts all of those by ignoring unparsed trailing characters.
uint16_t ParsePort(const std::string &s) {
    if (s.empty()) {
        throw std::invalid_argument("invalid port: " + s);
    }
    size_t consumed = 0;
    int value;
    try {
        value = std::stoi(s, &consumed);
    } catch (const std::exception &) {
        throw std::invalid_argument("invalid port: " + s);
    }
    if (consumed != s.size() || value < 0 || value > 65535) {
        throw std::invalid_argument("invalid port: " + s);
    }
    return static_cast<uint16_t>(value);
}

// "1.2.3.4:51820" or "[2001:db8::1]:51820" -> sockaddr_storage
sockaddr_storage ParseEndpoint(const std::string &endpoint) {
    sockaddr_storage ss{};
    std::memset(&ss, 0, sizeof(ss));

    size_t portSep;
    std::string host;
    uint16_t port;

    if (!endpoint.empty() && endpoint.front() == '[') {
        size_t close = endpoint.find(']');
        if (close == std::string::npos || close + 1 >= endpoint.size() || endpoint[close + 1] != ':') {
            throw std::invalid_argument("invalid IPv6 endpoint: " + endpoint);
        }
        host = endpoint.substr(1, close - 1);
        port = ParsePort(endpoint.substr(close + 2));

        auto *sin6 = reinterpret_cast<sockaddr_in6 *>(&ss);
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(port);
        if (inet_pton(AF_INET6, host.c_str(), &sin6->sin6_addr) != 1) {
            throw std::invalid_argument("invalid IPv6 address: " + host);
        }
        return ss;
    }

    portSep = endpoint.rfind(':');
    if (portSep == std::string::npos) {
        throw std::invalid_argument("invalid endpoint (expected host:port): " + endpoint);
    }
    host = endpoint.substr(0, portSep);
    port = ParsePort(endpoint.substr(portSep + 1));

    auto *sin = reinterpret_cast<sockaddr_in *>(&ss);
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &sin->sin_addr) != 1) {
        throw std::invalid_argument("invalid IPv4 address: " + host);
    }
    return ss;
}

std::string FormatEndpoint(const sockaddr *sa) {
    char ipBuf[INET6_ADDRSTRLEN] = {0};
    if (sa->sa_family == AF_INET) {
        const auto *sin = reinterpret_cast<const sockaddr_in *>(sa);
        inet_ntop(AF_INET, &sin->sin_addr, ipBuf, sizeof(ipBuf));
        return std::string(ipBuf) + ":" + std::to_string(ntohs(sin->sin_port));
    }
    const auto *sin6 = reinterpret_cast<const sockaddr_in6 *>(sa);
    inet_ntop(AF_INET6, &sin6->sin6_addr, ipBuf, sizeof(ipBuf));
    return std::string("[") + ipBuf + "]:" + std::to_string(ntohs(sin6->sin6_port));
}

void PutAllowedIPs(struct nlmsghdr *nlh, int parentAttr, const std::vector<wg::AllowedIP> &ips) {
    struct nlattr *ipsNest = mnl_attr_nest_start(nlh, parentAttr);
    for (size_t i = 0; i < ips.size(); i++) {
        const auto &aip = ips[i];
        struct nlattr *entry = mnl_attr_nest_start(nlh, static_cast<int>(i));
        mnl_attr_put_u16(nlh, WGALLOWEDIP_A_FAMILY, aip.family);
        if (aip.family == AF_INET) {
            in_addr addr{};
            inet_pton(AF_INET, aip.ip.c_str(), &addr);
            mnl_attr_put(nlh, WGALLOWEDIP_A_IPADDR, sizeof(addr), &addr);
        } else {
            in6_addr addr{};
            inet_pton(AF_INET6, aip.ip.c_str(), &addr);
            mnl_attr_put(nlh, WGALLOWEDIP_A_IPADDR, sizeof(addr), &addr);
        }
        mnl_attr_put_u8(nlh, WGALLOWEDIP_A_CIDR_MASK, aip.cidr);
        mnl_attr_nest_end(nlh, entry);
    }
    mnl_attr_nest_end(nlh, ipsNest);
}

int ParseAllowedIPAttr(const struct nlattr *attr, void *data) {
    auto *out = static_cast<wg::AllowedIP *>(data);
    switch (mnl_attr_get_type(attr)) {
        case WGALLOWEDIP_A_FAMILY:
            out->family = static_cast<uint8_t>(mnl_attr_get_u16(attr));
            break;
        case WGALLOWEDIP_A_IPADDR: {
            char buf[INET6_ADDRSTRLEN] = {0};
            const void *raw = mnl_attr_get_payload(attr);
            if (out->family == AF_INET6) {
                inet_ntop(AF_INET6, raw, buf, sizeof(buf));
            } else {
                inet_ntop(AF_INET, raw, buf, sizeof(buf));
            }
            out->ip = buf;
            break;
        }
        case WGALLOWEDIP_A_CIDR_MASK:
            out->cidr = mnl_attr_get_u8(attr);
            break;
        default:
            break;
    }
    return MNL_CB_OK;
}

int ParseAllowedIPEntry(const struct nlattr *attr, void *data) {
    auto *list = static_cast<std::vector<wg::AllowedIP> *>(data);
    wg::AllowedIP aip;
    mnl_attr_parse_nested(attr, ParseAllowedIPAttr, &aip);
    list->push_back(aip);
    return MNL_CB_OK;
}

int ParsePeerAttr(const struct nlattr *attr, void *data) {
    auto *peer = static_cast<wg::Peer *>(data);
    int type = mnl_attr_get_type(attr);
    switch (type) {
        case WGPEER_A_PUBLIC_KEY:
            std::memcpy(peer->publicKey.data(), mnl_attr_get_payload(attr), wg::kKeyLen);
            break;
        case WGPEER_A_PRESHARED_KEY: {
            wg::Key psk{};
            std::memcpy(psk.data(), mnl_attr_get_payload(attr), wg::kKeyLen);
            peer->presharedKey = psk;
            break;
        }
        case WGPEER_A_ENDPOINT: {
            const auto *sa = static_cast<const sockaddr *>(mnl_attr_get_payload(attr));
            peer->endpoint = FormatEndpoint(sa);
            break;
        }
        case WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL:
            peer->persistentKeepaliveInterval = mnl_attr_get_u16(attr);
            break;
        case WGPEER_A_LAST_HANDSHAKE_TIME: {
            // __kernel_timespec { int64 tv_sec; int64 tv_nsec; }
            const auto *raw = static_cast<const int64_t *>(mnl_attr_get_payload(attr));
            peer->lastHandshakeTimeSec = raw[0];
            break;
        }
        case WGPEER_A_RX_BYTES:
            peer->receiveBytes = mnl_attr_get_u64(attr);
            break;
        case WGPEER_A_TX_BYTES:
            peer->transmitBytes = mnl_attr_get_u64(attr);
            break;
        case WGPEER_A_ALLOWEDIPS:
            mnl_attr_parse_nested(attr, ParseAllowedIPEntry, &peer->allowedIPs);
            break;
        case WGPEER_A_PROTOCOL_VERSION:
            peer->protocolVersion = mnl_attr_get_u32(attr);
            break;
        default:
            break;
    }
    return MNL_CB_OK;
}

int ParsePeerEntry(const struct nlattr *attr, void *data) {
    auto *peers = static_cast<std::vector<wg::Peer> *>(data);
    wg::Peer peer;
    mnl_attr_parse_nested(attr, ParsePeerAttr, &peer);

    // When a peer's allowed-ips list is large, the kernel splits its dump across
    // multiple WGPEER_A_PEERS entries (possibly in separate netlink messages);
    // continuation entries repeat the same public key with only more allowed-ips.
    // `peers` accumulates across the whole multi-part dump (see ParseDeviceMessage),
    // so merging against the last entry catches splits across message boundaries too.
    if (!peers->empty() && peers->back().publicKey == peer.publicKey) {
        auto &existing = peers->back();
        existing.allowedIPs.insert(existing.allowedIPs.end(), peer.allowedIPs.begin(), peer.allowedIPs.end());
        return MNL_CB_OK;
    }

    peers->push_back(peer);
    return MNL_CB_OK;
}

int ParseDeviceAttr(const struct nlattr *attr, void *data) {
    auto *device = static_cast<wg::Device *>(data);
    int type = mnl_attr_get_type(attr);
    switch (type) {
        case WGDEVICE_A_IFNAME:
            device->name = mnl_attr_get_str(attr);
            break;
        case WGDEVICE_A_PRIVATE_KEY: {
            wg::Key key{};
            std::memcpy(key.data(), mnl_attr_get_payload(attr), wg::kKeyLen);
            device->privateKey = key;
            break;
        }
        case WGDEVICE_A_PUBLIC_KEY: {
            wg::Key key{};
            std::memcpy(key.data(), mnl_attr_get_payload(attr), wg::kKeyLen);
            device->publicKey = key;
            break;
        }
        case WGDEVICE_A_LISTEN_PORT:
            device->listenPort = mnl_attr_get_u16(attr);
            break;
        case WGDEVICE_A_FWMARK:
            device->firewallMark = mnl_attr_get_u32(attr);
            break;
        case WGDEVICE_A_PEERS:
            mnl_attr_parse_nested(attr, ParsePeerEntry, &device->peers);
            break;
        default:
            break;
    }
    return MNL_CB_OK;
}

} // namespace

wg::AllowedIP ParseCIDR(const std::string &cidr) {
    size_t slash = cidr.find('/');
    if (slash == std::string::npos) {
        throw std::invalid_argument("invalid CIDR (missing /mask): " + cidr);
    }
    std::string ip = cidr.substr(0, slash);
    std::string maskStr = cidr.substr(slash + 1);

    int mask;
    size_t consumed = 0;
    try {
        mask = std::stoi(maskStr, &consumed);
    } catch (const std::exception &) {
        throw std::invalid_argument("invalid CIDR mask: " + cidr);
    }
    if (consumed != maskStr.size()) {
        throw std::invalid_argument("invalid CIDR mask: " + cidr); // trailing garbage, e.g. "24abc"
    }

    wg::AllowedIP out;
    out.ip = ip;

    in6_addr v6{};
    if (inet_pton(AF_INET6, ip.c_str(), &v6) == 1) {
        out.family = AF_INET6;
        if (mask < 0 || mask > 128) {
            throw std::invalid_argument("invalid CIDR mask for IPv6 (must be 0-128): " + cidr);
        }
    } else {
        in_addr v4{};
        if (inet_pton(AF_INET, ip.c_str(), &v4) != 1) {
            throw std::invalid_argument("invalid CIDR address: " + ip);
        }
        out.family = AF_INET;
        if (mask < 0 || mask > 32) {
            throw std::invalid_argument("invalid CIDR mask for IPv4 (must be 0-32): " + cidr);
        }
    }

    out.cidr = static_cast<uint8_t>(mask);
    return out;
}

std::string FormatCIDR(const wg::AllowedIP &aip) {
    return aip.ip + "/" + std::to_string(aip.cidr);
}

void ValidateEndpoint(const std::string &endpoint) {
    (void)ParseEndpoint(endpoint);
}

struct nlmsghdr *BuildGetDeviceMessage(char *buf, uint16_t familyId, unsigned int seq, const std::string &ifname) {
    helpers::ValidateIfName(ifname);
    auto *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = familyId;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
    nlh->nlmsg_seq = seq;

    auto *genl = static_cast<struct genlmsghdr *>(mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr)));
    genl->cmd = WG_CMD_GET_DEVICE;
    genl->version = WG_GENL_VERSION;

    mnl_attr_put_strz(nlh, WGDEVICE_A_IFNAME, ifname.c_str());
    return nlh;
}

struct nlmsghdr *BuildSetDeviceMessage(char *buf, uint16_t familyId, unsigned int seq,
                                       const std::string &ifname, const wg::Config &cfg) {
    helpers::ValidateIfName(ifname);
    auto *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = familyId;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = seq;

    auto *genl = static_cast<struct genlmsghdr *>(mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr)));
    genl->cmd = WG_CMD_SET_DEVICE;
    genl->version = WG_GENL_VERSION;

    mnl_attr_put_strz(nlh, WGDEVICE_A_IFNAME, ifname.c_str());

    uint32_t flags = 0;
    if (cfg.replacePeers) {
        flags |= WGDEVICE_F_REPLACE_PEERS;
    }
    if (flags != 0) {
        mnl_attr_put_u32(nlh, WGDEVICE_A_FLAGS, flags);
    }

    if (cfg.privateKey) {
        mnl_attr_put(nlh, WGDEVICE_A_PRIVATE_KEY, wg::kKeyLen, cfg.privateKey->data());
    }
    if (cfg.listenPort) {
        mnl_attr_put_u16(nlh, WGDEVICE_A_LISTEN_PORT, *cfg.listenPort);
    }
    if (cfg.firewallMark) {
        mnl_attr_put_u32(nlh, WGDEVICE_A_FWMARK, *cfg.firewallMark);
    }

    if (!cfg.peers.empty()) {
        struct nlattr *peersNest = mnl_attr_nest_start(nlh, WGDEVICE_A_PEERS);
        for (size_t i = 0; i < cfg.peers.size(); i++) {
            const auto &peer = cfg.peers[i];
            struct nlattr *entry = mnl_attr_nest_start(nlh, static_cast<int>(i));

            mnl_attr_put(nlh, WGPEER_A_PUBLIC_KEY, wg::kKeyLen, peer.publicKey.data());

            uint32_t peerFlags = 0;
            if (peer.remove) peerFlags |= WGPEER_F_REMOVE_ME;
            if (peer.updateOnly) peerFlags |= WGPEER_F_UPDATE_ONLY;
            if (peer.replaceAllowedIPs) peerFlags |= WGPEER_F_REPLACE_ALLOWEDIPS;
            if (peerFlags != 0) {
                mnl_attr_put_u32(nlh, WGPEER_A_FLAGS, peerFlags);
            }

            if (peer.presharedKey) {
                mnl_attr_put(nlh, WGPEER_A_PRESHARED_KEY, wg::kKeyLen, peer.presharedKey->data());
            }
            if (peer.endpoint) {
                sockaddr_storage ss = ParseEndpoint(*peer.endpoint);
                size_t len = ss.ss_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
                mnl_attr_put(nlh, WGPEER_A_ENDPOINT, len, &ss);
            }
            if (peer.persistentKeepaliveInterval) {
                mnl_attr_put_u16(nlh, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, *peer.persistentKeepaliveInterval);
            }
            if (!peer.allowedIPs.empty()) {
                PutAllowedIPs(nlh, WGPEER_A_ALLOWEDIPS, peer.allowedIPs);
            }

            mnl_attr_nest_end(nlh, entry);
        }
        mnl_attr_nest_end(nlh, peersNest);
    }

    return nlh;
}

void ParseDeviceMessage(const struct nlmsghdr *nlh, wg::Device &outDevice) {
    mnl_attr_parse(nlh, sizeof(struct genlmsghdr), ParseDeviceAttr, &outDevice);
}

size_t EstimateSetDeviceMessageSize(const wg::Config &cfg) {
    // Generous per-element overestimates (nest headers + attr headers + padding)
    // rather than exact NLA_ALIGN math - this only sizes a scratch buffer.
    size_t total = 512; // nlmsghdr + genlmsghdr + ifname + scalar device attrs
    for (const auto &peer : cfg.peers) {
        total += 128; // peer nest header + public key/flags/psk/endpoint/keepalive
        total += peer.allowedIPs.size() * 64; // each allowedip entry, generously
    }
    return total;
}

} // namespace netlink
