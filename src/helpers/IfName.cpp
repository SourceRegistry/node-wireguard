#include "IfName.h"

#include <net/if.h>
#include <stdexcept>

namespace helpers {

void ValidateIfName(const std::string &name) {
    if (name.empty()) {
        throw std::invalid_argument("interface name must not be empty");
    }
    if (name == "." || name == "..") {
        throw std::invalid_argument("invalid interface name: " + name);
    }
    // IFNAMSIZ includes the terminating NUL the kernel appends.
    if (name.size() > IFNAMSIZ - 1) {
        throw std::invalid_argument("interface name too long (max " + std::to_string(IFNAMSIZ - 1) +
                                     " bytes): " + name);
    }
    for (char c : name) {
        if (c == '\0' || c == '/' || static_cast<unsigned char>(c) <= ' ') {
            throw std::invalid_argument("invalid character in interface name: " + name);
        }
    }
}

} // namespace helpers
