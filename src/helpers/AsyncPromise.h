#pragma once

#include <napi.h>
#include <cerrno>
#include <functional>
#include <stdexcept>
#include <string>

namespace helpers {

// Thrown from inside a PromiseWorker's execute function when a syscall fails;
// carries the errno so the JS side gets a matching err.code (e.g. 'ENODEV', 'EEXIST').
class SystemError : public std::runtime_error {
public:
    SystemError(int errnoCode, const std::string &message)
        : std::runtime_error(message), errnoCode_(errnoCode) {}

    int Code() const { return errnoCode_; }

private:
    int errnoCode_;
};

// Generic AsyncWorker -> Promise bridge. `execute` runs off the JS thread and
// either returns normally or throws (std::exception / SystemError); `resolve`
// runs back on the JS thread to build the resolved value from any captured state.
class PromiseWorker : public Napi::AsyncWorker {
public:
    using ExecuteFn = std::function<void()>;
    using ResolveFn = std::function<Napi::Value(Napi::Env)>;

    PromiseWorker(Napi::Env env, ExecuteFn execute, ResolveFn resolve = nullptr)
        : Napi::AsyncWorker(env),
          deferred_(Napi::Promise::Deferred::New(env)),
          execute_(std::move(execute)),
          resolve_(std::move(resolve)) {}

    Napi::Promise Promise() { return deferred_.Promise(); }

protected:
    void Execute() override {
        try {
            execute_();
        } catch (const SystemError &e) {
            errnoCode_ = e.Code();
            SetError(e.what());
        } catch (const std::exception &e) {
            SetError(e.what());
        }
    }

    void OnOK() override {
        Napi::Env env = Env();
        Napi::HandleScope scope(env);
        deferred_.Resolve(resolve_ ? resolve_(env) : env.Undefined());
    }

    void OnError(const Napi::Error &e) override {
        Napi::Env env = Env();
        Napi::HandleScope scope(env);
        Napi::Object errorObj = e.Value();
        if (errnoCode_ != 0) {
            errorObj.Set("code", Napi::String::New(env, ErrnoName(errnoCode_)));
            errorObj.Set("errno", Napi::Number::New(env, errnoCode_));
        }
        deferred_.Reject(errorObj);
    }

private:
    // Maps the small set of errno values this addon actually raises (see
    // WireGuardClient.cpp) to their symbolic names; falls back to "EUNKNOWN".
    static const char *ErrnoName(int code) {
        switch (code) {
            case ENODEV: return "ENODEV";
            case EEXIST: return "EEXIST";
            case ENOENT: return "ENOENT";
            case EPERM:  return "EPERM";
            case EACCES: return "EACCES";
            case EINVAL: return "EINVAL";
            case EBUSY:  return "EBUSY";
            default:     return "EUNKNOWN";
        }
    }

    Napi::Promise::Deferred deferred_;
    ExecuteFn execute_;
    ResolveFn resolve_;
    int errnoCode_ = 0;
};

} // namespace helpers
