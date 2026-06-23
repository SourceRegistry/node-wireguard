#include "UapiCodec.h"
#include "../crypto/Key.h"
#include "../helpers/AsyncPromise.h"
#include "../netlink/NlAttr.h" // reuse ParseCIDR/FormatCIDR - same "ip/mask" textual form as the netlink path

#include <sstream>
#include <stdexcept>

namespace uapi {

namespace {

// Strict unsigned decimal parser: rejects empty/non-numeric input, trailing
// garbage, and anything outside [0, max] - std::stoul alone accepts trailing
// garbage and returns a 64-bit value that a bare static_cast<uint16_t/32_t>
// would silently truncate instead of reject.
unsigned long ParseUnsignedInRange(const std::string &value, unsigned long max, const char *field) {
    if (value.empty()) {
        throw std::invalid_argument(std::string(field) + ": empty value");
    }
    size_t consumed = 0;
    unsigned long ul;
    try {
        ul = std::stoul(value, &consumed);
    } catch (const std::exception &) {
        throw std::invalid_argument(std::string(field) + ": invalid value: " + value);
    }
    if (consumed != value.size() || ul > max) {
        throw std::invalid_argument(std::string(field) + ": out of range: " + value);
    }
    return ul;
}

uint16_t ParseUint16(const std::string &value, const char *field) {
    return static_cast<uint16_t>(ParseUnsignedInRange(value, 65535, field));
}

uint32_t ParseUint32(const std::string &value, const char *field) {
    return static_cast<uint32_t>(ParseUnsignedInRange(value, 4294967295UL, field));
}

} // namespace

std::string BuildGetRequest() {
    return "get=1\n\n";
}

wg::Device ParseGetResponse(const std::string &name, const std::string &response) {
    wg::Device device;
    device.name = name;
    device.userspace = true;

    wg::Peer *currentPeer = nullptr;
    std::istringstream iss(response);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.empty()) {
            continue;
        }
        size_t eq = line.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        std::string key = line.substr(0, eq);
        std::string value = line.substr(eq + 1);

        if (key == "errno") {
            int code = std::stoi(value);
            if (code != 0) {
                throw helpers::SystemError(code, "uapi get error, errno=" + value);
            }
            continue;
        }

        if (key == "public_key") {
            // Starts a new peer section - everything until the next public_key=
            // (or end of message) belongs to it.
            device.peers.emplace_back();
            currentPeer = &device.peers.back();
            currentPeer->publicKey = crypto::KeyFromHex(value);
            continue;
        }

        if (currentPeer != nullptr) {
            if (key == "preshared_key") {
                currentPeer->presharedKey = crypto::KeyFromHex(value);
            } else if (key == "endpoint") {
                currentPeer->endpoint = value;
            } else if (key == "last_handshake_time_sec") {
                currentPeer->lastHandshakeTimeSec = std::stoll(value);
            } else if (key == "rx_bytes") {
                currentPeer->receiveBytes = std::stoull(value);
            } else if (key == "tx_bytes") {
                currentPeer->transmitBytes = std::stoull(value);
            } else if (key == "persistent_keepalive_interval") {
                currentPeer->persistentKeepaliveInterval = ParseUint16(value, "persistent_keepalive_interval");
            } else if (key == "allowed_ip") {
                currentPeer->allowedIPs.push_back(netlink::ParseCIDR(value));
            } else if (key == "protocol_version") {
                currentPeer->protocolVersion = ParseUint32(value, "protocol_version");
            }
            continue;
        }

        // Device-level fields (before the first peer section).
        if (key == "private_key") {
            device.privateKey = crypto::KeyFromHex(value);
        } else if (key == "listen_port") {
            device.listenPort = ParseUint16(value, "listen_port");
        } else if (key == "fwmark") {
            device.firewallMark = ParseUint32(value, "fwmark");
        }
    }

    if (device.privateKey && !crypto::IsZeroKey(*device.privateKey)) {
        device.publicKey = crypto::PublicKeyFromPrivate(*device.privateKey);
    }

    return device;
}

std::string BuildSetRequest(const wg::Config &cfg) {
    std::ostringstream oss;
    oss << "set=1\n";

    if (cfg.privateKey) {
        oss << "private_key=" << crypto::KeyToHex(*cfg.privateKey) << "\n";
    }
    if (cfg.listenPort) {
        oss << "listen_port=" << *cfg.listenPort << "\n";
    }
    if (cfg.firewallMark) {
        oss << "fwmark=" << *cfg.firewallMark << "\n";
    }
    if (cfg.replacePeers) {
        oss << "replace_peers=true\n";
    }

    for (const auto &peer : cfg.peers) {
        oss << "public_key=" << crypto::KeyToHex(peer.publicKey) << "\n";
        if (peer.remove) {
            oss << "remove=true\n";
        }
        if (peer.updateOnly) {
            oss << "update_only=true\n";
        }
        if (peer.presharedKey) {
            oss << "preshared_key=" << crypto::KeyToHex(*peer.presharedKey) << "\n";
        }
        if (peer.endpoint) {
            oss << "endpoint=" << *peer.endpoint << "\n";
        }
        if (peer.persistentKeepaliveInterval) {
            oss << "persistent_keepalive_interval=" << *peer.persistentKeepaliveInterval << "\n";
        }
        if (peer.replaceAllowedIPs) {
            oss << "replace_allowed_ips=true\n";
        }
        for (const auto &aip : peer.allowedIPs) {
            oss << "allowed_ip=" << netlink::FormatCIDR(aip) << "\n";
        }
    }

    oss << "\n";
    return oss.str();
}

void ParseSetResponse(const std::string &response) {
    std::istringstream iss(response);
    std::string line;
    while (std::getline(iss, line)) {
        size_t eq = line.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        if (line.substr(0, eq) == "errno") {
            int code = std::stoi(line.substr(eq + 1));
            if (code != 0) {
                throw helpers::SystemError(code, "uapi set error, errno=" + line.substr(eq + 1));
            }
        }
    }
}

} // namespace uapi
