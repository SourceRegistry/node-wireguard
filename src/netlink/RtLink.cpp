#include "RtLink.h"
#include "../helpers/AsyncPromise.h"
#include "../helpers/IfName.h"
#include "NlAttr.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <vector>

extern "C" {
#include <libmnl/libmnl.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
}

namespace netlink {

namespace {

const size_t kBufSize = MNL_SOCKET_BUFFER_SIZE;

// Opens a short-lived NETLINK_ROUTE socket, sends `nlh`, and waits for the ack.
// Throws helpers::SystemError on any netlink-reported or syscall errno.
void SendRtRequestAndWaitAck(struct nlmsghdr *nlh) {
    struct mnl_socket *sock = mnl_socket_open(NETLINK_ROUTE);
    if (!sock) {
        throw helpers::SystemError(errno, std::string("mnl_socket_open: ") + std::strerror(errno));
    }
    if (mnl_socket_bind(sock, 0, MNL_SOCKET_AUTOPID) < 0) {
        int err = errno;
        mnl_socket_close(sock);
        throw helpers::SystemError(err, std::string("mnl_socket_bind: ") + std::strerror(err));
    }

    uint32_t portid = mnl_socket_get_portid(sock);

    if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
        int err = errno;
        mnl_socket_close(sock);
        throw helpers::SystemError(err, std::string("mnl_socket_sendto: ") + std::strerror(err));
    }

    std::vector<char> buf(kBufSize);
    ssize_t ret = mnl_socket_recvfrom(sock, buf.data(), buf.size());
    mnl_socket_close(sock);

    if (ret < 0) {
        throw helpers::SystemError(errno, std::string("mnl_socket_recvfrom: ") + std::strerror(errno));
    }

    auto *replyHdr = reinterpret_cast<struct nlmsghdr *>(buf.data());
    if (replyHdr->nlmsg_seq != nlh->nlmsg_seq || replyHdr->nlmsg_pid != portid) {
        throw helpers::SystemError(EIO, "unexpected netlink reply (seq/pid mismatch)");
    }
    if (replyHdr->nlmsg_type == NLMSG_ERROR) {
        auto *err = static_cast<struct nlmsgerr *>(mnl_nlmsg_get_payload(replyHdr));
        if (err->error != 0) {
            int code = -err->error;
            throw helpers::SystemError(code, std::string("rtnetlink error: ") + std::strerror(code));
        }
    }
}

} // namespace

void CreateWireGuardLink(const std::string &name) {
    helpers::ValidateIfName(name);
    if (if_nametoindex(name.c_str()) != 0) {
        throw helpers::SystemError(EEXIST, "interface already exists: " + name);
    }

    std::vector<char> buf(kBufSize);
    auto *nlh = mnl_nlmsg_put_header(buf.data());
    nlh->nlmsg_type = RTM_NEWLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    nlh->nlmsg_seq = static_cast<unsigned int>(time(nullptr));

    auto *ifi = static_cast<struct ifinfomsg *>(mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg)));
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_change = 0xFFFFFFFF;

    mnl_attr_put_strz(nlh, IFLA_IFNAME, name.c_str());

    struct nlattr *linkinfo = mnl_attr_nest_start(nlh, IFLA_LINKINFO);
    mnl_attr_put_strz(nlh, IFLA_INFO_KIND, "wireguard");
    mnl_attr_nest_end(nlh, linkinfo);

    SendRtRequestAndWaitAck(nlh);
}

void DeleteLink(const std::string &name) {
    helpers::ValidateIfName(name);
    unsigned int ifindex = if_nametoindex(name.c_str());
    if (ifindex == 0) {
        throw helpers::SystemError(ENODEV, "no such interface: " + name);
    }

    std::vector<char> buf(kBufSize);
    auto *nlh = mnl_nlmsg_put_header(buf.data());
    nlh->nlmsg_type = RTM_DELLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = static_cast<unsigned int>(time(nullptr));

    auto *ifi = static_cast<struct ifinfomsg *>(mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg)));
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = static_cast<int>(ifindex);

    SendRtRequestAndWaitAck(nlh);
}

void SetLinkUp(const std::string &name, bool up) {
    helpers::ValidateIfName(name);
    unsigned int ifindex = if_nametoindex(name.c_str());
    if (ifindex == 0) {
        throw helpers::SystemError(ENODEV, "no such interface: " + name);
    }

    std::vector<char> buf(kBufSize);
    auto *nlh = mnl_nlmsg_put_header(buf.data());
    nlh->nlmsg_type = RTM_NEWLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = static_cast<unsigned int>(time(nullptr));

    auto *ifi = static_cast<struct ifinfomsg *>(mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg)));
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = static_cast<int>(ifindex);
    ifi->ifi_change = IFF_UP;
    ifi->ifi_flags = up ? IFF_UP : 0;

    SendRtRequestAndWaitAck(nlh);
}

namespace {
void BuildAddrRequest(std::vector<char> &buf, uint16_t msgType, uint16_t flags, unsigned int ifindex,
                      const wg::AllowedIP &addr) {
    auto *nlh = mnl_nlmsg_put_header(buf.data());
    nlh->nlmsg_type = msgType;
    nlh->nlmsg_flags = flags;
    nlh->nlmsg_seq = static_cast<unsigned int>(time(nullptr));

    auto *ifa = static_cast<struct ifaddrmsg *>(mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifaddrmsg)));
    ifa->ifa_family = addr.family;
    ifa->ifa_prefixlen = addr.cidr;
    ifa->ifa_flags = 0;
    ifa->ifa_scope = 0;
    ifa->ifa_index = ifindex;

    if (addr.family == AF_INET6) {
        in6_addr raw{};
        inet_pton(AF_INET6, addr.ip.c_str(), &raw);
        mnl_attr_put(nlh, IFA_LOCAL, sizeof(raw), &raw);
        mnl_attr_put(nlh, IFA_ADDRESS, sizeof(raw), &raw);
    } else {
        in_addr raw{};
        inet_pton(AF_INET, addr.ip.c_str(), &raw);
        mnl_attr_put(nlh, IFA_LOCAL, sizeof(raw), &raw);
        mnl_attr_put(nlh, IFA_ADDRESS, sizeof(raw), &raw);
    }
}
} // namespace

void AddAddress(const std::string &name, const std::string &cidr) {
    helpers::ValidateIfName(name);
    unsigned int ifindex = if_nametoindex(name.c_str());
    if (ifindex == 0) {
        throw helpers::SystemError(ENODEV, "no such interface: " + name);
    }
    wg::AllowedIP addr = ParseCIDR(cidr);

    std::vector<char> buf(kBufSize);
    BuildAddrRequest(buf, RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE, ifindex, addr);
    SendRtRequestAndWaitAck(reinterpret_cast<struct nlmsghdr *>(buf.data()));
}

void DeleteAddress(const std::string &name, const std::string &cidr) {
    helpers::ValidateIfName(name);
    unsigned int ifindex = if_nametoindex(name.c_str());
    if (ifindex == 0) {
        throw helpers::SystemError(ENODEV, "no such interface: " + name);
    }
    wg::AllowedIP addr = ParseCIDR(cidr);

    std::vector<char> buf(kBufSize);
    BuildAddrRequest(buf, RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK, ifindex, addr);
    SendRtRequestAndWaitAck(reinterpret_cast<struct nlmsghdr *>(buf.data()));
}

std::vector<std::string> ListWireGuardInterfaceNames() {
    std::vector<std::string> names;
    DIR *dir = opendir("/sys/class/net");
    if (!dir) {
        throw helpers::SystemError(errno, std::string("opendir(/sys/class/net): ") + std::strerror(errno));
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") {
            continue;
        }
        struct stat st{};
        std::string wgMarkerPath = "/sys/class/net/" + name + "/wireguard";
        if (stat(wgMarkerPath.c_str(), &st) == 0) {
            names.push_back(name);
        }
    }
    closedir(dir);
    return names;
}

} // namespace netlink
