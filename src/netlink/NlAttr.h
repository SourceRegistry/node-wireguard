#pragma once

#include "../WireGuardTypes.h"

extern "C" {
#include <libmnl/libmnl.h>
}

namespace netlink {

// Builds a WG_CMD_GET_DEVICE dump request for `ifname` into `buf`
// (caller-owned, must be >= MNL_SOCKET_BUFFER_SIZE). Returns the header.
struct nlmsghdr *BuildGetDeviceMessage(char *buf, uint16_t familyId, unsigned int seq, const std::string &ifname);

// Builds a WG_CMD_SET_DEVICE request applying `cfg` to `ifname` into `buf`.
// `buf` must be at least EstimateSetDeviceMessageSize(cfg) bytes - mnl_attr_put
// does not bounds-check, so an undersized buffer is a silent heap overflow.
struct nlmsghdr *BuildSetDeviceMessage(char *buf, uint16_t familyId, unsigned int seq,
                                       const std::string &ifname, const wg::Config &cfg);

// Upper-bound estimate (with margin) of the encoded size of a WG_CMD_SET_DEVICE
// message for `cfg`. A single peer's allowed-ips list has no fixed cap, so the
// fixed MNL_SOCKET_BUFFER_SIZE used for most requests is not safe to assume here.
size_t EstimateSetDeviceMessageSize(const wg::Config &cfg);

// Parses one WG_CMD_GET_DEVICE reply message, filling device-level fields on
// first call and appending any peers found in this message to outDevice.peers.
// If a peer's allowed-ips list is large enough that the kernel splits its dump
// across multiple WGPEER_A_PEERS entries (possibly across multiple messages),
// continuation entries are merged into the prior Peer by public key rather than
// kept as separate entries - see ParsePeerEntry in NlAttr.cpp.
void ParseDeviceMessage(const struct nlmsghdr *nlh, wg::Device &outDevice);

// "192.168.1.0/24" / "fd00::/64" -> AllowedIP. Throws std::invalid_argument on bad input.
wg::AllowedIP ParseCIDR(const std::string &cidr);

// AllowedIP -> "192.168.1.0/24" form.
std::string FormatCIDR(const wg::AllowedIP &aip);

} // namespace netlink
