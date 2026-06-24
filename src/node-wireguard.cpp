#include "WireGuardClient.h"
#include "crypto/Key.h"

#include <napi.h>
#include <stdexcept>

namespace {

Napi::Value GeneratePrivateKey(const Napi::CallbackInfo &info) {
    return Napi::String::New(info.Env(), crypto::KeyToBase64(crypto::GeneratePrivateKey()));
}

Napi::Value GeneratePresharedKey(const Napi::CallbackInfo &info) {
    return Napi::String::New(info.Env(), crypto::KeyToBase64(crypto::GeneratePresharedKey()));
}

Napi::Value PublicKey(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "publicKey(privateKey: string) expects a base64-encoded string").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    try {
        wg::Key priv = crypto::KeyFromBase64(info[0].As<Napi::String>().Utf8Value());
        return Napi::String::New(env, crypto::KeyToBase64(crypto::PublicKeyFromPrivate(priv)));
    } catch (const std::exception &e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Undefined();
    }
}

} // namespace

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("generatePrivateKey", Napi::Function::New(env, GeneratePrivateKey));
    exports.Set("generatePresharedKey", Napi::Function::New(env, GeneratePresharedKey));
    exports.Set("publicKey", Napi::Function::New(env, PublicKey));

    return WireGuardClient::Init(env, exports);
}

NODE_API_MODULE(node_wireguard, Init)
