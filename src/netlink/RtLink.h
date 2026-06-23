#pragma once

#include <string>
#include <vector>

namespace netlink {

// Lists interface names that are WireGuard devices, by checking for the
// presence of /sys/class/net/<name>/wireguard (exposed by the kernel module
// for any interface of kind "wireguard") — cheaper than an RTM_GETLINK dump
// plus IFLA_LINKINFO parsing for the same result.
std::vector<std::string> ListWireGuardInterfaceNames();

// Issues RTM_NEWLINK with IFLA_INFO_KIND="wireguard" to create a new WireGuard
// link. Throws helpers::SystemError(EEXIST) if `name` already exists, or other
// errno on failure (e.g. EPERM if not running as root / missing CAP_NET_ADMIN).
void CreateWireGuardLink(const std::string &name);

// Issues RTM_DELLINK for `name`. Throws helpers::SystemError(ENODEV) if it
// doesn't exist.
void DeleteLink(const std::string &name);

// Brings `name` administratively up (IFF_UP) or down via RTM_NEWLINK.
// Required for traffic to flow - createDevice() leaves the link down.
void SetLinkUp(const std::string &name, bool up);

// Assigns a local address ("10.0.0.2/24" or "fd00::2/64") to `name` via
// RTM_NEWADDR. Replaces any existing address with the same prefix.
void AddAddress(const std::string &name, const std::string &cidr);

// Removes a previously assigned address via RTM_DELADDR.
void DeleteAddress(const std::string &name, const std::string &cidr);

} // namespace netlink
