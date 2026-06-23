#include "WireGuardClient.h"
#include "WireGuardTypes.h"
#include "crypto/Key.h"
#include "helpers/AsyncPromise.h"
#include "netlink/NlAttr.h"
#include "netlink/RtLink.h"
#include "uapi/UapiCodec.h"
#include "uapi/UapiSocket.h"

extern "C" {
#include <libmnl/libmnl.h>
}

#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <unordered_set>
#include <vector>

namespace {

// Rejects, rather than silently truncating, a JS number that isn't an
// integer in [0, 65535] - Uint32Value()/static_cast<uint16_t> would otherwise
// wrap e.g. 70000 or -1 into an unrelated, valid-looking port/interval.
uint16_t RequireUint16(const Napi::Value &v, const char *field) {
    double d = v.As<Napi::Number>().DoubleValue();
    if (std::isnan(d) || std::floor(d) != d || d < 0 || d > 65535) {
        throw std::invalid_argument(std::string(field) + " must be an integer in 0..65535");
    }
    return static_cast<uint16_t>(d);
}

// Same rationale as RequireUint16 - Uint32Value() does an ECMAScript ToUint32
// conversion, which wraps negatives and non-integers instead of rejecting them.
uint32_t RequireUint32(const Napi::Value &v, const char *field) {
    double d = v.As<Napi::Number>().DoubleValue();
    if (std::isnan(d) || std::floor(d) != d || d < 0 || d > 4294967295.0) {
        throw std::invalid_argument(std::string(field) + " must be an integer in 0..4294967295");
    }
    return static_cast<uint32_t>(d);
}

std::string RequireString(const Napi::Object &obj, const char *key) {
    Napi::Value v = obj.Get(key);
    if (!v.IsString()) {
        throw std::invalid_argument(std::string(key) + " must be a string");
    }
    return v.As<Napi::String>().Utf8Value();
}

// Reads info[idx] as a string into `out`. Returns false (leaving `out`
// untouched) if the argument is missing or not a string, so callers can
// reject the returned Promise instead of letting a failed N-API cast
// (NAPI_DISABLE_CPP_EXCEPTIONS is set - see binding.gyp) throw synchronously
// from a method that's documented to always return a Promise.
bool GetStringArg(const Napi::CallbackInfo &info, size_t idx, std::string &out) {
    if (info.Length() <= idx || !info[idx].IsString()) {
        return false;
    }
    out = info[idx].As<Napi::String>().Utf8Value();
    return true;
}

Napi::Promise RejectPromise(Napi::Env env, const std::string &message) {
    auto deferred = Napi::Promise::Deferred::New(env);
    deferred.Reject(Napi::Error::New(env, message).Value());
    return deferred.Promise();
}

// --- native -> JS -------------------------------------------------------

Napi::Object PeerToJs(Napi::Env env, const wg::Peer &peer) {
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("publicKey", crypto::KeyToBase64(peer.publicKey));
    // The kernel/UAPI always report this attribute, even when unset (as an
    // all-zero key) - normalize that to '' to match the documented "no preshared key" case.
    bool hasPsk = peer.presharedKey && !crypto::IsZeroKey(*peer.presharedKey);
    obj.Set("presharedKey", hasPsk ? crypto::KeyToBase64(*peer.presharedKey) : std::string());
    if (peer.endpoint) {
        obj.Set("endpoint", *peer.endpoint);
    } else {
        obj.Set("endpoint", env.Undefined());
    }
    obj.Set("persistentKeepaliveInterval", peer.persistentKeepaliveInterval);
    if (peer.lastHandshakeTimeSec > 0) {
        obj.Set("lastHandshakeTime", Napi::Date::New(env, static_cast<double>(peer.lastHandshakeTimeSec) * 1000.0));
    } else {
        obj.Set("lastHandshakeTime", env.Null());
    }
    obj.Set("receiveBytes", Napi::BigInt::New(env, peer.receiveBytes));
    obj.Set("transmitBytes", Napi::BigInt::New(env, peer.transmitBytes));

    Napi::Array ips = Napi::Array::New(env, peer.allowedIPs.size());
    for (size_t i = 0; i < peer.allowedIPs.size(); i++) {
        ips.Set(static_cast<uint32_t>(i), netlink::FormatCIDR(peer.allowedIPs[i]));
    }
    obj.Set("allowedIPs", ips);
    obj.Set("protocolVersion", peer.protocolVersion);
    return obj;
}

Napi::Object DeviceToJs(Napi::Env env, const wg::Device &dev) {
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("name", dev.name);
    obj.Set("type", dev.userspace ? "userspace" : "linux-kernel");
    obj.Set("privateKey", dev.privateKey ? crypto::KeyToBase64(*dev.privateKey) : std::string());
    obj.Set("publicKey", dev.publicKey ? crypto::KeyToBase64(*dev.publicKey) : std::string());
    obj.Set("listenPort", dev.listenPort);
    obj.Set("firewallMark", dev.firewallMark);

    Napi::Array peers = Napi::Array::New(env, dev.peers.size());
    for (size_t i = 0; i < dev.peers.size(); i++) {
        peers.Set(static_cast<uint32_t>(i), PeerToJs(env, dev.peers[i]));
    }
    obj.Set("peers", peers);
    return obj;
}

// --- JS -> native --------------------------------------------------------

wg::PeerConfig PeerConfigFromJs(const Napi::Object &obj) {
    wg::PeerConfig pc;
    pc.publicKey = crypto::KeyFromBase64(RequireString(obj, "publicKey"));

    if (obj.Has("remove") && obj.Get("remove").IsBoolean()) {
        pc.remove = obj.Get("remove").As<Napi::Boolean>().Value();
    }
    if (obj.Has("updateOnly") && obj.Get("updateOnly").IsBoolean()) {
        pc.updateOnly = obj.Get("updateOnly").As<Napi::Boolean>().Value();
    }
    if (obj.Has("presharedKey") && obj.Get("presharedKey").IsString()) {
        pc.presharedKey = crypto::KeyFromBase64(RequireString(obj, "presharedKey"));
    }
    if (obj.Has("endpoint") && obj.Get("endpoint").IsString()) {
        pc.endpoint = obj.Get("endpoint").As<Napi::String>().Utf8Value();
    }
    if (obj.Has("persistentKeepaliveInterval") && obj.Get("persistentKeepaliveInterval").IsNumber()) {
        pc.persistentKeepaliveInterval =
            RequireUint16(obj.Get("persistentKeepaliveInterval"), "persistentKeepaliveInterval");
    }
    if (obj.Has("replaceAllowedIPs") && obj.Get("replaceAllowedIPs").IsBoolean()) {
        pc.replaceAllowedIPs = obj.Get("replaceAllowedIPs").As<Napi::Boolean>().Value();
    }
    if (obj.Has("allowedIPs") && obj.Get("allowedIPs").IsArray()) {
        Napi::Array arr = obj.Get("allowedIPs").As<Napi::Array>();
        for (uint32_t i = 0; i < arr.Length(); i++) {
            Napi::Value item = arr.Get(i);
            if (!item.IsString()) {
                throw std::invalid_argument("allowedIPs entries must be strings");
            }
            pc.allowedIPs.push_back(netlink::ParseCIDR(item.As<Napi::String>().Utf8Value()));
        }
    }
    return pc;
}

wg::Config ConfigFromJs(const Napi::Object &obj) {
    wg::Config cfg;
    if (obj.Has("privateKey") && obj.Get("privateKey").IsString()) {
        cfg.privateKey = crypto::KeyFromBase64(RequireString(obj, "privateKey"));
    }
    if (obj.Has("listenPort") && obj.Get("listenPort").IsNumber()) {
        cfg.listenPort = RequireUint16(obj.Get("listenPort"), "listenPort");
    }
    if (obj.Has("firewallMark") && obj.Get("firewallMark").IsNumber()) {
        cfg.firewallMark = RequireUint32(obj.Get("firewallMark"), "firewallMark");
    }
    if (obj.Has("replacePeers") && obj.Get("replacePeers").IsBoolean()) {
        cfg.replacePeers = obj.Get("replacePeers").As<Napi::Boolean>().Value();
    }
    if (obj.Has("peers") && obj.Get("peers").IsArray()) {
        Napi::Array arr = obj.Get("peers").As<Napi::Array>();
        for (uint32_t i = 0; i < arr.Length(); i++) {
            Napi::Value item = arr.Get(i);
            if (!item.IsObject()) {
                throw std::invalid_argument("peers entries must be objects");
            }
            cfg.peers.push_back(PeerConfigFromJs(item.As<Napi::Object>()));
        }
    }
    return cfg;
}

// Runs one WG_CMD_GET_DEVICE dump for `name` against `sock` and returns the
// assembled Device. Must only be called from a PromiseWorker's Execute()
// (background thread) - touches no Napi:: types.
wg::Device FetchDeviceKernel(netlink::NlSocket &sock, const std::string &name) {
    uint16_t familyId = sock.WireGuardFamilyId();
    std::vector<char> buf(MNL_SOCKET_BUFFER_SIZE);
    unsigned int seq = sock.NextSeq();
    auto *nlh = netlink::BuildGetDeviceMessage(buf.data(), familyId, seq, name);

    wg::Device device;
    device.name = name;
    sock.SendAndReceive(nlh, [&](const struct nlmsghdr *reply) {
        netlink::ParseDeviceMessage(reply, device);
        return true;
    });
    return device;
}

// Fetches one device, dispatching to the UAPI socket backend (userspace
// implementations like wireguard-go) if one is present for `name`, otherwise
// the kernel netlink backend. Must only be called off the JS thread.
wg::Device FetchDevice(netlink::NlSocket &sock, const std::string &name) {
    if (uapi::HasSocket(name)) {
        std::string response = uapi::Transact(name, uapi::BuildGetRequest());
        return uapi::ParseGetResponse(name, response);
    }
    return FetchDeviceKernel(sock, name);
}

// Applies `cfg` to `name`, dispatching to the UAPI socket backend if present,
// otherwise kernel netlink. Must only be called off the JS thread.
void ApplyConfig(netlink::NlSocket &sock, const std::string &name, const wg::Config &cfg) {
    if (uapi::HasSocket(name)) {
        std::string response = uapi::Transact(name, uapi::BuildSetRequest(cfg));
        uapi::ParseSetResponse(response);
        return;
    }

    uint16_t familyId = sock.WireGuardFamilyId();
    size_t bufSize = std::max<size_t>(MNL_SOCKET_BUFFER_SIZE, netlink::EstimateSetDeviceMessageSize(cfg));
    std::vector<char> buf(bufSize);
    unsigned int seq = sock.NextSeq();
    auto *nlh = netlink::BuildSetDeviceMessage(buf.data(), familyId, seq, name, cfg);
    sock.SendAndReceive(nlh, [](const struct nlmsghdr *) { return true; });
}

} // namespace

Napi::Object WireGuardClient::Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(env, "WireGuardClient", {
        InstanceMethod("createDevice", &WireGuardClient::CreateDevice),
        InstanceMethod("deleteDevice", &WireGuardClient::DeleteDevice),
        InstanceMethod("devices", &WireGuardClient::Devices),
        InstanceMethod("device", &WireGuardClient::Device),
        InstanceMethod("configureDevice", &WireGuardClient::ConfigureDevice),
        InstanceMethod("setUp", &WireGuardClient::SetUp),
        InstanceMethod("setDown", &WireGuardClient::SetDown),
        InstanceMethod("setAddress", &WireGuardClient::SetAddress),
        InstanceMethod("deleteAddress", &WireGuardClient::DeleteAddress),
        InstanceMethod("close", &WireGuardClient::Close),
    });

    exports.Set("WireGuardClient", func);
    return exports;
}

WireGuardClient::WireGuardClient(const Napi::CallbackInfo &info) : Napi::ObjectWrap<WireGuardClient>(info) {
    Napi::Env env = info.Env();
    try {
        sock_ = std::make_shared<netlink::NlSocket>();
    } catch (const std::exception &e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
    }
}

Napi::Value WireGuardClient::CreateDevice(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    if (!sock_) {
        // Reject (not throw synchronously) - every other method here returns a
        // Promise, and a sync throw from a Promise-returning method breaks
        // callers using `await`/`assert.rejects` against it.
        auto deferred = Napi::Promise::Deferred::New(env);
        deferred.Reject(Napi::Error::New(env, "client is closed").Value());
        return deferred.Promise();
    }
    std::string name;
    if (!GetStringArg(info, 0, name)) {
        return RejectPromise(env, "expected interface name (string) as argument 0");
    }

    auto *worker = new helpers::PromiseWorker(env, [name]() { netlink::CreateWireGuardLink(name); });
    worker->Queue();
    return worker->Promise();
}

Napi::Value WireGuardClient::DeleteDevice(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    if (!sock_) {
        // Reject (not throw synchronously) - every other method here returns a
        // Promise, and a sync throw from a Promise-returning method breaks
        // callers using `await`/`assert.rejects` against it.
        auto deferred = Napi::Promise::Deferred::New(env);
        deferred.Reject(Napi::Error::New(env, "client is closed").Value());
        return deferred.Promise();
    }
    std::string name;
    if (!GetStringArg(info, 0, name)) {
        return RejectPromise(env, "expected interface name (string) as argument 0");
    }

    auto *worker = new helpers::PromiseWorker(env, [name]() { netlink::DeleteLink(name); });
    worker->Queue();
    return worker->Promise();
}

Napi::Value WireGuardClient::Devices(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    if (!sock_) {
        // Reject (not throw synchronously) - every other method here returns a
        // Promise, and a sync throw from a Promise-returning method breaks
        // callers using `await`/`assert.rejects` against it.
        auto deferred = Napi::Promise::Deferred::New(env);
        deferred.Reject(Napi::Error::New(env, "client is closed").Value());
        return deferred.Promise();
    }
    auto sock = sock_;
    auto results = std::make_shared<std::vector<wg::Device>>();

    auto *worker = new helpers::PromiseWorker(
        env,
        [sock, results]() {
            // A name can't be both kernel- and UAPI-backed (the kernel module's
            // /sys/class/net/<name>/wireguard marker and a userspace daemon's
            // socket are mutually exclusive in practice), so a plain set union
            // is enough - no risk of double-fetching the same interface.
            std::unordered_set<std::string> names;
            for (auto &name : netlink::ListWireGuardInterfaceNames()) {
                names.insert(std::move(name));
            }
            for (auto &name : uapi::ListInterfaceNames()) {
                names.insert(std::move(name));
            }
            for (const auto &name : names) {
                results->push_back(FetchDevice(*sock, name));
            }
        },
        [results](Napi::Env resolveEnv) -> Napi::Value {
            Napi::Array arr = Napi::Array::New(resolveEnv, results->size());
            for (size_t i = 0; i < results->size(); i++) {
                arr.Set(static_cast<uint32_t>(i), DeviceToJs(resolveEnv, (*results)[i]));
            }
            return arr;
        });
    worker->Queue();
    return worker->Promise();
}

Napi::Value WireGuardClient::Device(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    if (!sock_) {
        // Reject (not throw synchronously) - every other method here returns a
        // Promise, and a sync throw from a Promise-returning method breaks
        // callers using `await`/`assert.rejects` against it.
        auto deferred = Napi::Promise::Deferred::New(env);
        deferred.Reject(Napi::Error::New(env, "client is closed").Value());
        return deferred.Promise();
    }
    std::string name;
    if (!GetStringArg(info, 0, name)) {
        return RejectPromise(env, "expected interface name (string) as argument 0");
    }
    auto sock = sock_;
    auto result = std::make_shared<wg::Device>();

    auto *worker = new helpers::PromiseWorker(
        env,
        [sock, name, result]() { *result = FetchDevice(*sock, name); },
        [result](Napi::Env resolveEnv) -> Napi::Value { return DeviceToJs(resolveEnv, *result); });
    worker->Queue();
    return worker->Promise();
}

Napi::Value WireGuardClient::ConfigureDevice(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    if (!sock_) {
        // Reject (not throw synchronously) - every other method here returns a
        // Promise, and a sync throw from a Promise-returning method breaks
        // callers using `await`/`assert.rejects` against it.
        auto deferred = Napi::Promise::Deferred::New(env);
        deferred.Reject(Napi::Error::New(env, "client is closed").Value());
        return deferred.Promise();
    }
    std::string name;
    if (!GetStringArg(info, 0, name)) {
        return RejectPromise(env, "expected interface name (string) as argument 0");
    }
    if (info.Length() <= 1 || !info[1].IsObject()) {
        return RejectPromise(env, "expected config (object) as argument 1");
    }

    wg::Config cfg;
    try {
        // Must parse here (main thread) - Napi types are unsafe to touch off-thread.
        // ConfigFromJs/PeerConfigFromJs/ParseCIDR/KeyFromBase64 can throw on bad
        // input (e.g. out-of-range CIDR mask). configureDevice() is documented as
        // Promise-returning, so this must reject rather than throw synchronously
        // (and rejecting, not throwing, is what an uncaught C++ exception across
        // the N-API boundary would otherwise risk turning into a process crash).
        cfg = ConfigFromJs(info[1].As<Napi::Object>());
    } catch (const std::exception &e) {
        auto deferred = Napi::Promise::Deferred::New(env);
        deferred.Reject(Napi::Error::New(env, e.what()).Value());
        return deferred.Promise();
    }
    auto sock = sock_;

    auto *worker = new helpers::PromiseWorker(env, [sock, name, cfg]() { ApplyConfig(*sock, name, cfg); });
    worker->Queue();
    return worker->Promise();
}

Napi::Value WireGuardClient::SetUp(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    if (!sock_) {
        // Reject (not throw synchronously) - every other method here returns a
        // Promise, and a sync throw from a Promise-returning method breaks
        // callers using `await`/`assert.rejects` against it.
        auto deferred = Napi::Promise::Deferred::New(env);
        deferred.Reject(Napi::Error::New(env, "client is closed").Value());
        return deferred.Promise();
    }
    std::string name;
    if (!GetStringArg(info, 0, name)) {
        return RejectPromise(env, "expected interface name (string) as argument 0");
    }

    auto *worker = new helpers::PromiseWorker(env, [name]() { netlink::SetLinkUp(name, true); });
    worker->Queue();
    return worker->Promise();
}

Napi::Value WireGuardClient::SetDown(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    if (!sock_) {
        // Reject (not throw synchronously) - every other method here returns a
        // Promise, and a sync throw from a Promise-returning method breaks
        // callers using `await`/`assert.rejects` against it.
        auto deferred = Napi::Promise::Deferred::New(env);
        deferred.Reject(Napi::Error::New(env, "client is closed").Value());
        return deferred.Promise();
    }
    std::string name;
    if (!GetStringArg(info, 0, name)) {
        return RejectPromise(env, "expected interface name (string) as argument 0");
    }

    auto *worker = new helpers::PromiseWorker(env, [name]() { netlink::SetLinkUp(name, false); });
    worker->Queue();
    return worker->Promise();
}

Napi::Value WireGuardClient::SetAddress(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    if (!sock_) {
        // Reject (not throw synchronously) - every other method here returns a
        // Promise, and a sync throw from a Promise-returning method breaks
        // callers using `await`/`assert.rejects` against it.
        auto deferred = Napi::Promise::Deferred::New(env);
        deferred.Reject(Napi::Error::New(env, "client is closed").Value());
        return deferred.Promise();
    }
    std::string name;
    std::string cidr;
    if (!GetStringArg(info, 0, name) || !GetStringArg(info, 1, cidr)) {
        return RejectPromise(env, "expected interface name and cidr (strings)");
    }

    auto *worker = new helpers::PromiseWorker(env, [name, cidr]() { netlink::AddAddress(name, cidr); });
    worker->Queue();
    return worker->Promise();
}

Napi::Value WireGuardClient::DeleteAddress(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    if (!sock_) {
        // Reject (not throw synchronously) - every other method here returns a
        // Promise, and a sync throw from a Promise-returning method breaks
        // callers using `await`/`assert.rejects` against it.
        auto deferred = Napi::Promise::Deferred::New(env);
        deferred.Reject(Napi::Error::New(env, "client is closed").Value());
        return deferred.Promise();
    }
    std::string name;
    std::string cidr;
    if (!GetStringArg(info, 0, name) || !GetStringArg(info, 1, cidr)) {
        return RejectPromise(env, "expected interface name and cidr (strings)");
    }

    auto *worker = new helpers::PromiseWorker(env, [name, cidr]() { netlink::DeleteAddress(name, cidr); });
    worker->Queue();
    return worker->Promise();
}

Napi::Value WireGuardClient::Close(const Napi::CallbackInfo &info) {
    sock_.reset();
    return info.Env().Undefined();
}
