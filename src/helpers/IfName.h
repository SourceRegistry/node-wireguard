#pragma once

#include <string>

namespace helpers {

// Validates `name` as a Linux network interface name: non-empty, no NUL or
// '/' characters, not "." or "..", and short enough to fit IFNAMSIZ
// (including the kernel's terminating NUL). Throws std::invalid_argument
// otherwise. Every native entry point that turns a JS-supplied string into
// an ifname (netlink attribute, rtnetlink lookup, or UAPI socket path) must
// call this first - mnl_attr_put_strz does not bounds-check, and an
// unvalidated name can also be used for path traversal against the UAPI
// socket directory.
void ValidateIfName(const std::string &name);

} // namespace helpers
