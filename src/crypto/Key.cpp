#include "Key.h"

#include <algorithm>
#include <sodium.h>
#include <stdexcept>
#include <vector>

namespace crypto {

namespace {
void ClampScalar(wg::Key &key) {
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
}
} // namespace

wg::Key GeneratePrivateKey() {
    wg::Key key{};
    randombytes_buf(key.data(), wg::kKeyLen);
    ClampScalar(key);
    return key;
}

wg::Key GeneratePresharedKey() {
    wg::Key key{};
    randombytes_buf(key.data(), wg::kKeyLen);
    return key;
}

wg::Key PublicKeyFromPrivate(const wg::Key &privateKey) {
    wg::Key pub{};
    if (crypto_scalarmult_base(pub.data(), privateKey.data()) != 0) {
        throw std::runtime_error("crypto_scalarmult_base failed");
    }
    return pub;
}

std::string KeyToBase64(const wg::Key &key) {
    // sodium_base64_ENCODED_LEN includes the null terminator.
    std::vector<char> out(sodium_base64_ENCODED_LEN(wg::kKeyLen, sodium_base64_VARIANT_ORIGINAL));
    sodium_bin2base64(out.data(), out.size(), key.data(), wg::kKeyLen, sodium_base64_VARIANT_ORIGINAL);
    return std::string(out.data());
}

wg::Key KeyFromBase64(const std::string &b64) {
    wg::Key key{};
    size_t decodedLen = 0;
    if (sodium_base642bin(key.data(), wg::kKeyLen, b64.c_str(), b64.size(), nullptr, &decodedLen,
                           nullptr, sodium_base64_VARIANT_ORIGINAL) != 0 ||
        decodedLen != wg::kKeyLen) {
        throw std::invalid_argument("invalid base64-encoded WireGuard key: " + b64);
    }
    return key;
}

std::string KeyToHex(const wg::Key &key) {
    std::vector<char> out(wg::kKeyLen * 2 + 1); // 2 hex chars/byte + '\0', per sodium_bin2hex's hex_maxlen contract
    sodium_bin2hex(out.data(), out.size(), key.data(), wg::kKeyLen);
    return std::string(out.data());
}

wg::Key KeyFromHex(const std::string &hex) {
    wg::Key key{};
    size_t decodedLen = 0;
    if (sodium_hex2bin(key.data(), wg::kKeyLen, hex.c_str(), hex.size(), nullptr, &decodedLen, nullptr) != 0 ||
        decodedLen != wg::kKeyLen) {
        throw std::invalid_argument("invalid hex-encoded WireGuard key: " + hex);
    }
    return key;
}

bool IsZeroKey(const wg::Key &key) {
    return std::all_of(key.begin(), key.end(), [](uint8_t b) { return b == 0; });
}

} // namespace crypto
