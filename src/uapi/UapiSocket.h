#pragma once

#include <string>
#include <vector>

namespace uapi {

// Default search path for a userspace WireGuard implementation's (e.g.
// wireguard-go) control socket. wgctrl-go's wguser backend also checks
// $XDG_RUNTIME_DIR/wireguard first; not implemented here (v1 is Linux-only
// and most wireguard-go deployments use the /var/run path).
extern const char *const kSocketDir;

// True if a UAPI control socket exists for `name` - used to decide whether
// to dispatch a given interface to the kernel-netlink or UAPI backend.
bool HasSocket(const std::string &name);

// Lists interface names that have a UAPI control socket present.
std::vector<std::string> ListInterfaceNames();

// Connects to the UAPI socket for `name`, writes `request` in full, then reads
// the full response (the server closes the connection after one request/response
// - see wireguard-go's ipc_linux.go). Throws helpers::SystemError on any failure,
// with ENOENT if the socket doesn't exist.
std::string Transact(const std::string &name, const std::string &request);

} // namespace uapi
