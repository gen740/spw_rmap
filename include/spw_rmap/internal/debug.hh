#pragma once

#include <atomic>
#include <iostream>
#include <source_location>

#ifndef SPW_RMAP_DEBUG
#define SPW_RMAP_DEBUG 0
#endif

namespace spw_rmap::debug {

inline constexpr bool kEnabled = SPW_RMAP_DEBUG;

#if SPW_RMAP_DEBUG
namespace detail {
auto RuntimeFlag() noexcept -> std::atomic<bool>&;
}  // namespace detail

inline void SetRuntimeEnabled(bool value) noexcept {
  detail::RuntimeFlag().store(value, std::memory_order_relaxed);
}

[[nodiscard]] inline auto IsRuntimeEnabled() noexcept -> bool {
  return detail::RuntimeFlag().load(std::memory_order_relaxed);
}
#else
inline void set_runtime_enabled(bool) noexcept {}
[[nodiscard]] inline constexpr auto is_runtime_enabled() noexcept -> bool {
  return false;
}
#endif

inline void Enable() noexcept { SetRuntimeEnabled(true); }
inline void Disable() noexcept { SetRuntimeEnabled(false); }

template <typename T>
void DebugImpl(T&& msg, const std::source_location& loc =
                            std::source_location::current()) {
  std::cerr << loc.file_name() << " in line " << loc.line() << " in function "
            << loc.function_name() << ": " << std::forward<T>(msg) << '\n';
}

template <typename T>
constexpr void Debug(T&& msg, const std::source_location& loc =
                                  std::source_location::current()) {
  if constexpr (kEnabled) {
    if (IsRuntimeEnabled()) {
      DebugImpl(std::forward<T>(msg), loc);
    }
  }
}

template <typename T, typename Arg>
void DebugImpl(
    T&& msg, Arg&& value,
    const std::source_location& loc = std::source_location::current()) {
  std::cerr << loc.file_name() << " in line " << loc.line() << " in function "
            << loc.function_name() << ": " << std::forward<T>(msg)
            << std::forward<Arg>(value) << '\n';
}

template <typename T, typename Arg>
constexpr void Debug(
    T&& msg, Arg&& value,
    const std::source_location& loc = std::source_location::current()) {
  if constexpr (kEnabled) {
    if (IsRuntimeEnabled()) {
      DebugImpl(std::forward<T>(msg), std::forward<Arg>(value), loc);
    }
  }
}

}  // namespace spw_rmap::debug
