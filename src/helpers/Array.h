#pragma once

#include <napi.h>
#include <string>
#include <vector>

namespace helpers {

inline Napi::Array StringVectorToJS(Napi::Env env, const std::vector<std::string> &items) {
    Napi::Array arr = Napi::Array::New(env, items.size());
    for (size_t i = 0; i < items.size(); i++) {
        arr.Set(i, Napi::String::New(env, items[i]));
    }
    return arr;
}

inline std::vector<std::string> JSArrayToStringVector(const Napi::Array &arr) {
    std::vector<std::string> out;
    out.reserve(arr.Length());
    for (uint32_t i = 0; i < arr.Length(); i++) {
        out.push_back(arr.Get(i).As<Napi::String>().Utf8Value());
    }
    return out;
}

} // namespace helpers
