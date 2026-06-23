#pragma once

#include "../WireGuardTypes.h"

namespace crypto {

// Generates a 32-byte Curve25519 private key, clamped per RFC7748 (same
// clamping `wg genkey` applies), from libsodium's CSPRNG.
wg::Key GeneratePrivateKey();

// Generates an opaque 32-byte preshared key (raw random bytes, not a scalar).
wg::Key GeneratePresharedKey();

// Computes the X25519 public key for a (clamped) private key.
wg::Key PublicKeyFromPrivate(const wg::Key &privateKey);

// Base64 (standard, padded) encode/decode, matching wgtypes.Key.String()/ParseKey().
std::string KeyToBase64(const wg::Key &key);
wg::Key KeyFromBase64(const std::string &b64); // throws std::invalid_argument if not 32 bytes decoded

// Lowercase hex encode/decode - the key encoding the cross-platform userspace
// UAPI protocol uses (https://www.wireguard.com/xplatform/), distinct from the
// base64 form used by the kernel netlink path / `wg` CLI.
std::string KeyToHex(const wg::Key &key);
wg::Key KeyFromHex(const std::string &hex); // throws std::invalid_argument if not 32 bytes decoded

// True if every byte is zero - the UAPI/netlink convention for "field unset".
bool IsZeroKey(const wg::Key &key);

} // namespace crypto
