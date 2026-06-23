#pragma once

#include "netlink/NlSocket.h"

#include <memory>
#include <napi.h>

// N-API class mirroring wgctrl-go's *wgctrl.Client, extended with interface
// lifecycle (createDevice/deleteDevice) since this addon — unlike wgctrl-go —
// also owns creating/destroying the WireGuard link itself (see plan decision:
// "full lifecycle"). One instance owns one genetlink socket for its lifetime.
class WireGuardClient : public Napi::ObjectWrap<WireGuardClient> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    explicit WireGuardClient(const Napi::CallbackInfo &info);

private:
    Napi::Value CreateDevice(const Napi::CallbackInfo &info);
    Napi::Value DeleteDevice(const Napi::CallbackInfo &info);
    Napi::Value Devices(const Napi::CallbackInfo &info);
    Napi::Value Device(const Napi::CallbackInfo &info);
    Napi::Value ConfigureDevice(const Napi::CallbackInfo &info);
    Napi::Value SetUp(const Napi::CallbackInfo &info);
    Napi::Value SetDown(const Napi::CallbackInfo &info);
    Napi::Value SetAddress(const Napi::CallbackInfo &info);
    Napi::Value DeleteAddress(const Napi::CallbackInfo &info);
    Napi::Value Close(const Napi::CallbackInfo &info);

    // Shared (not owned exclusively) so an in-flight AsyncWorker keeps the
    // socket alive even if the JS wrapper is closed/GC'd before it finishes.
    std::shared_ptr<netlink::NlSocket> sock_;
};
