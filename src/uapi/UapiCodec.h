#pragma once

#include "../WireGuardTypes.h"

namespace uapi {

// Builds a `get=1\n...\n\n` request body (just the literal request - no I/O).
std::string BuildGetRequest();

// Parses the response to a `get=1` request into a Device. Throws
// helpers::SystemError if the response's errno field is non-zero.
wg::Device ParseGetResponse(const std::string &name, const std::string &response);

// Builds a `set=1\n...\n\n` request applying `cfg`, per
// https://www.wireguard.com/xplatform/'s wire format.
std::string BuildSetRequest(const wg::Config &cfg);

// Parses the response to a `set=1` request. Throws helpers::SystemError if
// the response's errno field is non-zero.
void ParseSetResponse(const std::string &response);

} // namespace uapi
