#include "NlSocket.h"
#include "../helpers/AsyncPromise.h"
#include "wireguard_uapi.h"

#include <cerrno>
#include <cstring>
#include <vector>

extern "C" {
#include <linux/genetlink.h>
#include <linux/netlink.h>
}

namespace netlink {

namespace {
const size_t kBufSize = MNL_SOCKET_BUFFER_SIZE;

int FamilyIdAttrCallback(const struct nlattr *attr, void *data) {
    auto *out = static_cast<uint16_t *>(data);
    if (mnl_attr_get_type(attr) == CTRL_ATTR_FAMILY_ID) {
        *out = mnl_attr_get_u16(attr);
    }
    return MNL_CB_OK;
}

int FamilyIdMsgCallback(const struct nlmsghdr *nlh, void *data) {
    return mnl_attr_parse(nlh, sizeof(struct genlmsghdr), FamilyIdAttrCallback, data);
}
} // namespace

NlSocket::NlSocket() {
    sock_ = mnl_socket_open(NETLINK_GENERIC);
    if (!sock_) {
        throw helpers::SystemError(errno, std::string("mnl_socket_open: ") + std::strerror(errno));
    }
    if (mnl_socket_bind(sock_, 0, MNL_SOCKET_AUTOPID) < 0) {
        int err = errno;
        mnl_socket_close(sock_);
        sock_ = nullptr;
        throw helpers::SystemError(err, std::string("mnl_socket_bind: ") + std::strerror(err));
    }
    portid_ = mnl_socket_get_portid(sock_);
}

NlSocket::~NlSocket() {
    if (sock_) {
        mnl_socket_close(sock_);
    }
}

void NlSocket::SendAndReceive(struct nlmsghdr *nlh, const MessageHandler &handler) {
    unsigned int seq = nlh->nlmsg_seq;

    if (mnl_socket_sendto(sock_, nlh, nlh->nlmsg_len) < 0) {
        throw helpers::SystemError(errno, std::string("mnl_socket_sendto: ") + std::strerror(errno));
    }

    std::vector<char> buf(kBufSize);
    for (;;) {
        ssize_t ret = mnl_socket_recvfrom(sock_, buf.data(), buf.size());
        if (ret < 0) {
            throw helpers::SystemError(errno, std::string("mnl_socket_recvfrom: ") + std::strerror(errno));
        }
        if (ret == 0) {
            break;
        }

        // Walk every nlmsghdr in this datagram (a dump reply can pack several).
        // mnl_nlmsg_ok/mnl_nlmsg_next take `int *`, not `size_t *` - aliasing a
        // size_t through an int* is undefined behavior (and only happened to
        // work here on little-endian, by luck).
        auto *cur = reinterpret_cast<struct nlmsghdr *>(buf.data());
        int remaining = static_cast<int>(ret);
        bool done = false;
        while (mnl_nlmsg_ok(cur, remaining)) {
            if (cur->nlmsg_seq != seq || cur->nlmsg_pid != portid_) {
                cur = mnl_nlmsg_next(cur, &remaining);
                continue;
            }
            if (cur->nlmsg_type == NLMSG_ERROR) {
                auto *err = static_cast<struct nlmsgerr *>(mnl_nlmsg_get_payload(cur));
                if (err->error != 0) {
                    int code = -err->error;
                    throw helpers::SystemError(code, std::string("netlink error: ") + std::strerror(code));
                }
                done = true;
                break;
            }
            if (cur->nlmsg_type == NLMSG_DONE) {
                done = true;
                break;
            }
            if (!handler(cur)) {
                done = true;
                break;
            }
            if (!(cur->nlmsg_flags & NLM_F_MULTI)) {
                done = true;
                break;
            }
            cur = mnl_nlmsg_next(cur, &remaining);
        }
        if (done) {
            break;
        }
    }
}

uint16_t NlSocket::WireGuardFamilyId() {
    if (wgFamilyId_ != 0) {
        return wgFamilyId_;
    }

    std::vector<char> buf(kBufSize);
    unsigned int seq = NextSeq();

    auto *nlh = mnl_nlmsg_put_header(buf.data());
    nlh->nlmsg_type = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = seq;

    auto *genl = static_cast<struct genlmsghdr *>(mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr)));
    genl->cmd = CTRL_CMD_GETFAMILY;
    genl->version = 1;

    mnl_attr_put_strz(nlh, CTRL_ATTR_FAMILY_NAME, WG_GENL_NAME);

    uint16_t familyId = 0;
    SendAndReceive(nlh, [&](const struct nlmsghdr *reply) {
        FamilyIdMsgCallback(reply, &familyId);
        return true;
    });

    if (familyId == 0) {
        throw helpers::SystemError(ENODEV, "wireguard genetlink family not found (is the wireguard kernel module loaded?)");
    }

    wgFamilyId_ = familyId;
    return wgFamilyId_;
}

} // namespace netlink
