cmake_minimum_required(VERSION 3.16)

project(node_wireguard_native LANGUAGES CXX)

# This project is built by node-gyp via binding.gyp. The custom target exists
# so C++ IDEs have a native project target for indexing all addon sources.
add_custom_target(node-wireguard-sources SOURCES
    src/node-wireguard.cpp
    src/WireGuardClient.cpp
    src/WireGuardClient.h
    src/WireGuardTypes.h
    src/crypto/Key.cpp
    src/crypto/Key.h
    src/helpers/Array.h
    src/helpers/AsyncPromise.h
    src/helpers/IfName.cpp
    src/helpers/IfName.h
    src/netlink/NlAttr.cpp
    src/netlink/NlAttr.h
    src/netlink/NlSocket.cpp
    src/netlink/NlSocket.h
    src/netlink/RtLink.cpp
    src/netlink/RtLink.h
    src/netlink/wireguard_uapi.h
    src/uapi/UapiCodec.cpp
    src/uapi/UapiCodec.h
    src/uapi/UapiSocket.cpp
    src/uapi/UapiSocket.h
)
