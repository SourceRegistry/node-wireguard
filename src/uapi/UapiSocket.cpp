#include "UapiSocket.h"
#include "../helpers/AsyncPromise.h"
#include "../helpers/IfName.h"

#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>

namespace uapi {

const char *const kSocketDir = "/var/run/wireguard";
constexpr size_t kMaxResponseBytes = 1024 * 1024;
constexpr time_t kIoTimeoutSeconds = 5;

namespace {

// `name` must be validated before being interpolated into a filesystem path -
// otherwise a name containing '/' or ".." lets a caller traverse outside
// kSocketDir (see HasSocket/Transact below, the only callers).
std::string SocketPath(const std::string &name) {
    helpers::ValidateIfName(name);
    return std::string(kSocketDir) + "/" + name + ".sock";
}

} // namespace

bool HasSocket(const std::string &name) {
    std::string path = SocketPath(name);
    return access(path.c_str(), F_OK) == 0;
}

std::vector<std::string> ListInterfaceNames() {
    std::vector<std::string> names;
    DIR *dir = opendir(kSocketDir);
    if (!dir) {
        return names; // directory not present - no userspace interfaces, not an error
    }

    struct dirent *entry;
    constexpr const char *suffix = ".sock";
    const size_t suffixLen = 5;
    while ((entry = readdir(dir)) != nullptr) {
        std::string fname = entry->d_name;
        if (fname.size() > suffixLen && fname.compare(fname.size() - suffixLen, suffixLen, suffix) == 0) {
            std::string name = fname.substr(0, fname.size() - suffixLen);
            try {
                helpers::ValidateIfName(name);
                names.push_back(name);
            } catch (const std::invalid_argument &) {
                // Ignore files that cannot be legitimate WireGuard interface
                // control sockets. This keeps devices() from failing because
                // of unrelated or malicious entries in the socket directory.
            }
        }
    }
    closedir(dir);
    return names;
}

std::string Transact(const std::string &name, const std::string &request) {
    std::string path = SocketPath(name);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        throw helpers::SystemError(errno, std::string("socket: ") + std::strerror(errno));
    }

    timeval timeout{};
    timeout.tv_sec = kIoTimeoutSeconds;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        int err = errno;
        close(fd);
        throw helpers::SystemError(err, std::string("setsockopt timeout: ") + std::strerror(err));
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (path.size() >= sizeof(addr.sun_path)) {
        close(fd);
        throw std::invalid_argument("uapi socket path too long: " + path);
    }
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        int err = errno;
        close(fd);
        throw helpers::SystemError(err, std::string("connect(") + path + "): " + std::strerror(err));
    }

    size_t written = 0;
    while (written < request.size()) {
        ssize_t n = write(fd, request.data() + written, request.size() - written);
        if (n < 0) {
            int err = errno;
            close(fd);
            throw helpers::SystemError(err, std::string("write: ") + std::strerror(err));
        }
        written += static_cast<size_t>(n);
    }

    // Some UAPI servers (e.g. wireguard-go) keep the connection open across
    // multiple operations, only closing once they see EOF on their next read.
    // Half-close our write side so the server's next read gets that EOF and it
    // closes the connection (after flushing the response already written) -
    // otherwise both sides block waiting for the other to close first.
    if (shutdown(fd, SHUT_WR) < 0) {
        int err = errno;
        close(fd);
        throw helpers::SystemError(err, std::string("shutdown: ") + std::strerror(err));
    }

    std::string response;
    char buf[4096];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            int err = errno;
            close(fd);
            throw helpers::SystemError(err, std::string("read: ") + std::strerror(err));
        }
        if (n == 0) {
            break; // EOF - server closes after responding
        }
        if (response.size() + static_cast<size_t>(n) > kMaxResponseBytes) {
            close(fd);
            throw std::runtime_error("uapi response exceeded 1048576 bytes");
        }
        response.append(buf, static_cast<size_t>(n));
    }

    close(fd);
    return response;
}

} // namespace uapi
