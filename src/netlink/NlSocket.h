#pragma once

#include <functional>
#include <string>

extern "C" {
#include <libmnl/libmnl.h>
}

namespace netlink {

// Thin wrapper around a single NETLINK_GENERIC mnl_socket: resolves the
// "wireguard" generic-netlink family once, then sends/receives messages
// against it. One instance is owned by WireGuardClient for its lifetime.
class NlSocket {
public:
    using MessageHandler = std::function<bool(const struct nlmsghdr *)>; // return false to stop early

    NlSocket();
    ~NlSocket();

    NlSocket(const NlSocket &) = delete;
    NlSocket &operator=(const NlSocket &) = delete;

    // Resolves and caches the "wireguard" genl family id. Throws helpers::SystemError(ENODEV)
    // if the wireguard kernel module isn't loaded / family doesn't exist.
    uint16_t WireGuardFamilyId();

    // Sends `nlh` (already built via mnl_nlmsg_put_header against this socket's nl buffer)
    // and feeds every reply message to `handler` until the kernel signals completion
    // (NLMSG_DONE for dumps, or a single ack/reply for non-dump requests).
    void SendAndReceive(struct nlmsghdr *nlh, const MessageHandler &handler);

    uint32_t Portid() const { return portid_; }
    unsigned int NextSeq() { return ++seq_; }

private:
    struct mnl_socket *sock_ = nullptr;
    uint32_t portid_ = 0;
    unsigned int seq_ = 0;
    uint16_t wgFamilyId_ = 0;
};

} // namespace netlink
