#include "Key.h"

#include <algorithm>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <vector>

namespace crypto {

namespace {

void ClampScalar(wg::Key &key) {
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
}

constexpr char kBase64Chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// -1 = invalid character, otherwise the 6-bit value.
int8_t Base64DecodeChar(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return static_cast<int8_t>(c - 'A');
    if (c >= 'a' && c <= 'z') return static_cast<int8_t>(c - 'a' + 26);
    if (c >= '0' && c <= '9') return static_cast<int8_t>(c - '0' + 52);
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

constexpr char kHexChars[] = "0123456789abcdef";

int8_t HexDecodeChar(unsigned char c) {
    if (c >= '0' && c <= '9') return static_cast<int8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<int8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<int8_t>(c - 'A' + 10);
    return -1;
}

} // namespace

wg::Key GeneratePrivateKey() {
    wg::Key key{};
    if (RAND_bytes(key.data(), static_cast<int>(wg::kKeyLen)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    ClampScalar(key);
    return key;
}

wg::Key GeneratePresharedKey() {
    wg::Key key{};
    if (RAND_bytes(key.data(), static_cast<int>(wg::kKeyLen)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return key;
}

wg::Key PublicKeyFromPrivate(const wg::Key &privateKey) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, privateKey.data(), wg::kKeyLen);
    if (!pkey) {
        throw std::runtime_error("EVP_PKEY_new_raw_private_key failed");
    }

    wg::Key pub{};
    size_t pubLen = wg::kKeyLen;
    int ok = EVP_PKEY_get_raw_public_key(pkey, pub.data(), &pubLen);
    EVP_PKEY_free(pkey);

    if (ok != 1 || pubLen != wg::kKeyLen) {
        throw std::runtime_error("EVP_PKEY_get_raw_public_key failed");
    }
    return pub;
}

std::string KeyToBase64(const wg::Key &key) {
    std::string out;
    out.reserve(44); // ceil(32/3)*4
    size_t i = 0;
    for (; i + 3 <= wg::kKeyLen; i += 3) {
        uint32_t n = (static_cast<uint32_t>(key[i]) << 16) | (static_cast<uint32_t>(key[i + 1]) << 8) | key[i + 2];
        out += kBase64Chars[(n >> 18) & 0x3F];
        out += kBase64Chars[(n >> 12) & 0x3F];
        out += kBase64Chars[(n >> 6) & 0x3F];
        out += kBase64Chars[n & 0x3F];
    }
    const size_t rem = wg::kKeyLen - i;
    if (rem == 1) {
        uint32_t n = static_cast<uint32_t>(key[i]) << 16;
        out += kBase64Chars[(n >> 18) & 0x3F];
        out += kBase64Chars[(n >> 12) & 0x3F];
        out += "==";
    } else if (rem == 2) {
        uint32_t n = (static_cast<uint32_t>(key[i]) << 16) | (static_cast<uint32_t>(key[i + 1]) << 8);
        out += kBase64Chars[(n >> 18) & 0x3F];
        out += kBase64Chars[(n >> 12) & 0x3F];
        out += kBase64Chars[(n >> 6) & 0x3F];
        out += "=";
    }
    return out;
}

wg::Key KeyFromBase64(const std::string &b64) {
    // Standard padded base64 of 32 bytes is always 44 chars ("...==" or "...=" never happens
    // for 32 bytes specifically - 32 % 3 == 2, so exactly one trailing '=').
    std::string s = b64;
    while (!s.empty() && s.back() == '=') s.pop_back();
    if (s.size() != 43) {
        throw std::invalid_argument("invalid base64-encoded WireGuard key: " + b64);
    }

    wg::Key key{};
    size_t outPos = 0;
    int32_t buf = 0;
    int bits = 0;
    for (char c : s) {
        int8_t v = Base64DecodeChar(static_cast<unsigned char>(c));
        if (v < 0) {
            throw std::invalid_argument("invalid base64-encoded WireGuard key: " + b64);
        }
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (outPos >= wg::kKeyLen) {
                throw std::invalid_argument("invalid base64-encoded WireGuard key: " + b64);
            }
            key[outPos++] = static_cast<uint8_t>((buf >> bits) & 0xFF);
        }
    }
    if (outPos != wg::kKeyLen) {
        throw std::invalid_argument("invalid base64-encoded WireGuard key: " + b64);
    }
    return key;
}

std::string KeyToHex(const wg::Key &key) {
    std::string out;
    out.reserve(wg::kKeyLen * 2);
    for (uint8_t b : key) {
        out += kHexChars[b >> 4];
        out += kHexChars[b & 0x0F];
    }
    return out;
}

wg::Key KeyFromHex(const std::string &hex) {
    if (hex.size() != wg::kKeyLen * 2) {
        throw std::invalid_argument("invalid hex-encoded WireGuard key: " + hex);
    }
    wg::Key key{};
    for (size_t i = 0; i < wg::kKeyLen; ++i) {
        int8_t hi = HexDecodeChar(static_cast<unsigned char>(hex[i * 2]));
        int8_t lo = HexDecodeChar(static_cast<unsigned char>(hex[i * 2 + 1]));
        if (hi < 0 || lo < 0) {
            throw std::invalid_argument("invalid hex-encoded WireGuard key: " + hex);
        }
        key[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return key;
}

bool IsZeroKey(const wg::Key &key) {
    return std::all_of(key.begin(), key.end(), [](uint8_t b) { return b == 0; });
}

} // namespace crypto
