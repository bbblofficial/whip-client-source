// ===== file: antidebug/stack/stack_cpp.hpp =====
//
// C++ wrapper for the stack-protection module — RAII guards, variadic
// cloaked-call template, profile-aware init.
//
// Header-only. Pulls in the C headers under extern "C" and adds C++ niceties:
//
//   - ad::StackProtect       — RAII handle around ad_stack_protect_init/shutdown
//   - ad::StackHidden        — RAII guard for moonwalk (auto-restore on exit)
//   - ad::cloaked            — variadic template that wraps CloakedCallN
//   - ad::spoof_my_ra()      — __forceinline wrapper of ad_main_ra_spoof
//   - ad::flood_run          — exception-safe stack-flood scope (see A4)
//
// Requires C++17 or later.
//
#ifndef ANTIDEBUG_STACK_CPP_HPP
#define ANTIDEBUG_STACK_CPP_HPP

#ifndef __cplusplus
#  error "stack_cpp.hpp requires C++"
#endif

#include <cstdint>
#include <tuple>
#include <type_traits>
#include <utility>

extern "C" {
#include "stack_protect.h"
#include "cloaked_call.h"
#include "main_ra_spoof.h"
#include "moonwalk.h"
#include "stack_flood.h"
}

namespace ad {

// ---------------------------------------------------------------------------
// StackProtect — RAII handle. One-liner activation in main().
//
//     int main() {
//         ad::spoof_my_ra();         // overwrite main's saved RA
//         ad::StackProtect protect;  // gadget+decoy pools, noise threads
//         ...
//     }
// ---------------------------------------------------------------------------
class StackProtect {
    ad_stack_protect_t* h_;
public:
    explicit StackProtect(std::uint32_t flags = AD_SP_PROFILE_BALANCED)
        : h_(ad_stack_protect_init(flags)) {}

    ~StackProtect() { if (h_) ad_stack_protect_shutdown(h_); }

    StackProtect(const StackProtect&)            = delete;
    StackProtect& operator=(const StackProtect&) = delete;
    StackProtect(StackProtect&& o) noexcept : h_(o.h_) { o.h_ = nullptr; }

    [[nodiscard]] ad_stack_protect_t* handle() const noexcept { return h_; }

    [[nodiscard]] const ad_gadget_table_t* gadgets() const noexcept {
        return ad_stack_protect_gadgets(h_);
    }
    [[nodiscard]] const ad_decoy_table_t* decoys() const noexcept {
        return ad_stack_protect_decoys(h_);
    }
    [[nodiscard]] void* pick_decoy(std::uint32_t n = 0) const noexcept {
        return ad_stack_protect_pick_decoy(h_, n);
    }
};

// ---------------------------------------------------------------------------
// spoof_my_ra() — overwrite the saved RA of the function that called us.
//
// MUST be __forceinline so _AddressOfReturnAddress (inside ad_main_ra_spoof)
// resolves to the caller's RA slot, not this wrapper's. Use as the very
// first statement of main():
//
//     int main() { ad::spoof_my_ra(); ... }
// ---------------------------------------------------------------------------
__forceinline void spoof_my_ra() noexcept {
    ad_main_ra_spoof();
}

// ---------------------------------------------------------------------------
// StackHidden — moonwalk RAII guard. Spoofs the RA of the function the
// guard is constructed in; restores on destruction (any path, including
// exceptions).
//
//     void critical() {
//         ad::StackHidden guard;     // current frame's RA → ntdll decoy
//         do_sensitive_work();
//     }
//
// Pass an explicit decoy to override the auto-pick from the singleton.
// ---------------------------------------------------------------------------
class StackHidden {
    ad_moonwalk_ctx_t ctx_{};
public:
    __forceinline StackHidden() noexcept {
        // Pull decoy from the singleton if it's been initialized; otherwise
        // become a no-op (ad_moonwalk_begin tolerates a null decoy).
        void* decoy = ad_stack_protect_pick_decoy(ad_stack_protect_singleton(), 0u);
        ad_moonwalk_begin(&ctx_, decoy);
    }
    __forceinline explicit StackHidden(void* decoy) noexcept {
        ad_moonwalk_begin(&ctx_, decoy);
    }
    __forceinline ~StackHidden() noexcept { ad_moonwalk_end(&ctx_); }

    StackHidden(const StackHidden&)            = delete;
    StackHidden& operator=(const StackHidden&) = delete;
};

// ---------------------------------------------------------------------------
// cloaked(fn, args...) — variadic template wrapper.
//
// Uses the existing CloakedCall1 (single-pointer arg) underneath: we pack
// the call into a stack-local lambda-state and dispatch through a C-linkage
// thunk. Works for any signature, including non-pointer args and any return
// type (void / arithmetic / pointer / class).
//
//     int x = ad::cloaked(&compute, 42, 0.5, "hello");
//     ad::cloaked(&do_work);                     // void return, no args
//     auto* p = ad::cloaked(&allocate, 1024u);
// ---------------------------------------------------------------------------
// (Internal detail namespace removed: the previous `cloaked_thunk` template
//  was dead code — `cloaked()` below uses local stateless lambdas that decay
//  to function pointers, no template thunk needed. Removed to avoid the
//  invalid `template<...> extern "C"` combination MSVC rejects.)

template <typename Fn, typename... Args>
auto cloaked(Fn&& fn, Args&&... args) {
    using FnD = std::decay_t<Fn>;
    using R   = std::invoke_result_t<FnD, Args...>;

    if constexpr (std::is_void_v<R>) {
        struct State {
            FnD fn;
            std::tuple<std::decay_t<Args>...> args;
        } s{ std::forward<Fn>(fn), std::tuple<std::decay_t<Args>...>(std::forward<Args>(args)...) };

        auto thunk = +[](void* p) -> void* {
            auto* st = static_cast<State*>(p);
            std::apply(st->fn, st->args);
            return nullptr;
        };
        CloakedCall1(reinterpret_cast<void*>(thunk), &s);
        return;
    } else {
        struct State {
            FnD fn;
            std::tuple<std::decay_t<Args>...> args;
            alignas(R) unsigned char result_storage[sizeof(R)];
        } s{ std::forward<Fn>(fn), std::tuple<std::decay_t<Args>...>(std::forward<Args>(args)...), {} };

        auto thunk = +[](void* p) -> void* {
            auto* st = static_cast<State*>(p);
            ::new (st->result_storage) R(std::apply(st->fn, st->args));
            return nullptr;
        };
        CloakedCall1(reinterpret_cast<void*>(thunk), &s);
        R out = std::move(*reinterpret_cast<R*>(s.result_storage));
        reinterpret_cast<R*>(s.result_storage)->~R();
        return out;
    }
}

// ---------------------------------------------------------------------------
// flood_run(body) — A4: exception-safe stack flood.
//
// The body callable runs with the entire stack polluted; `__try/__finally`
// guarantees the flood is undone even if body throws or raises SEH.
//
// Caller must have an initialized StackProtect with both gadget+decoy pools.
//
// Note: requires SEH (MSVC). Uses a plain function-pointer body to keep
// out of the way of C++ exceptions; lambdas without captures decay to
// function pointers naturally.
// ---------------------------------------------------------------------------
inline void flood_run(const StackProtect& sp,
                      void (*body)(void*),
                      void* arg = nullptr) {
    ad_flood_run_protected(sp.handle(), body, arg);
}

} // namespace ad

#endif // ANTIDEBUG_STACK_CPP_HPP
