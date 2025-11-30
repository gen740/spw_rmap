#pragma once

#include <atomic>
#include <iostream>
#include <source_location>

#ifndef SPW_RMAP_DEBUG
#define SPW_RMAP_DEBUG 0
#endif

namespace spw_rmap::debug {

inline constexpr bool enabled = static_cast<bool>(SPW_RMAP_DEBUG);

#if SPW_RMAP_DEBUG
namespace detail {
auto runtime_flag() noexcept -> std::atomic<bool>&;
}  // namespace detail

inline void set_runtime_enabled(bool value) noexcept {
  detail::runtime_flag().store(value, std::memory_order_relaxed);
}

[[nodiscard]] inline auto is_runtime_enabled() noexcept -> bool {
  return detail::runtime_flag().load(std::memory_order_relaxed);
}
#else
inline void set_runtime_enabled(bool) noexcept {}
[[nodiscard]] inline constexpr auto is_runtime_enabled() noexcept -> bool {
  return false;
}
#endif

inline void enable() noexcept { set_runtime_enabled(true); }
inline void disable() noexcept { set_runtime_enabled(false); }

template <typename T>
void debug_impl(T&& msg, const std::source_location& loc =
                             std::source_location::current()) {
  std::cerr << loc.file_name() << " in line " << loc.line() << " in function "
            << loc.function_name() << ": " << std::forward<T>(msg) << '\n';
}

template <typename T>
constexpr void debug(T&& msg, const std::source_location& loc =
                                  std::source_location::current()) {
  if constexpr (enabled) {
    if (is_runtime_enabled()) {
      debug_impl(std::forward<T>(msg), loc);
    }
  }
}

template <typename T, typename Arg>
void debug_impl(
    T&& msg, Arg&& value,
    const std::source_location& loc = std::source_location::current()) {
  std::cerr << loc.file_name() << " in line " << loc.line() << " in function "
            << loc.function_name() << ": " << std::forward<T>(msg)
            << std::forward<Arg>(value) << '\n';
}

template <typename T, typename Arg>
constexpr void debug(
    T&& msg, Arg&& value,
    const std::source_location& loc = std::source_location::current()) {
  if constexpr (enabled) {
    if (is_runtime_enabled()) {
      debug_impl(std::forward<T>(msg), std::forward<Arg>(value), loc);
    }
  }
}

}  // namespace spw_rmap::debug
