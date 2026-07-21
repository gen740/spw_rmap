// Copyright (c) 2025 Gen
// Licensed under the MIT License. See LICENSE file for details.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

namespace spw_rmap {

namespace detail {

// Called when an address setter is given more than TargetNode::kMaxAddressLen
// bytes: logs the offending lengths to std::cerr and calls std::terminate().
// An oversized address is a programming error, not a recoverable condition.
// Defined in src/target_node.cc so this header stays free of <iostream>.
[[noreturn]] void FailAddressTooLong(const char* what, std::size_t actual,
                                     std::size_t max);

}  // namespace detail

class TargetNode {
 public:
  static constexpr std::size_t kMaxAddressLen = 12;

 private:
  static constexpr uint8_t kDefaultLogicalAddress = 0xEF;

  uint8_t logical_address_{kDefaultLogicalAddress};
  std::array<uint8_t, kMaxAddressLen> target_{};
  std::array<uint8_t, kMaxAddressLen> reply_{};
  uint8_t target_len_{0};
  uint8_t reply_len_{0};

 public:
  // Single constructor with a default argument: also serves as the default
  // constructor, so `TargetNode{}` is unambiguous. The default logical address
  // matches kDefaultLogicalAddress (>= 0x20, i.e. a valid RMAP logical address
  // the packet builders accept).
  [[nodiscard]] constexpr TargetNode(
      uint8_t logical_address = kDefaultLogicalAddress) noexcept
      : logical_address_(logical_address) {}

  [[nodiscard]] constexpr auto GetTargetLogicalAddress() const noexcept
      -> uint8_t {
    return logical_address_;
  }

  [[nodiscard]] constexpr auto GetTargetAddress() const noexcept
      -> std::span<const uint8_t> {
    return {target_.data(), target_len_};
  }

  [[nodiscard]] constexpr auto GetReplyAddress() const noexcept
      -> std::span<const uint8_t> {
    return {reply_.data(), reply_len_};
  }

  constexpr auto SetTargetLogicalAddress(uint8_t logical_address) noexcept
      -> TargetNode& {
    logical_address_ = logical_address;
    return *this;
  }

  template <class... Bs>
    requires(sizeof...(Bs) <= kMaxAddressLen &&
             (std::is_convertible_v<Bs, uint8_t> && ...))
  constexpr auto SetTargetAddress(Bs... bs) noexcept -> TargetNode& {
    target_len_ = static_cast<uint8_t>(sizeof...(Bs));
    std::size_t i = 0;
    ((target_[i++] = static_cast<uint8_t>(bs)), ...);  // NOLINT
    return *this;
  }

  template <class... Bs>
    requires(sizeof...(Bs) <= kMaxAddressLen &&
             (std::is_convertible_v<Bs, uint8_t> && ...))
  constexpr auto SetReplyAddress(Bs... bs) noexcept -> TargetNode& {
    reply_len_ = static_cast<uint8_t>(sizeof...(Bs));
    std::size_t i = 0;
    ((reply_[i++] = static_cast<uint8_t>(bs)), ...);  // NOLINT
    return *this;
  }

  constexpr auto SetTargetAddress(std::span<const uint8_t> addr) noexcept
      -> TargetNode& {
    if (addr.size() > kMaxAddressLen) [[unlikely]] {
      detail::FailAddressTooLong("TargetNode target address", addr.size(),
                                 kMaxAddressLen);
    }
    target_len_ = static_cast<uint8_t>(addr.size());
    for (std::size_t i = 0; i < addr.size(); ++i) {
      target_[i] = addr[i];  // NOLINT
    }
    return *this;
  }

  constexpr auto SetReplyAddress(std::span<const uint8_t> addr) noexcept
      -> TargetNode& {
    if (addr.size() > kMaxAddressLen) [[unlikely]] {
      detail::FailAddressTooLong("TargetNode reply address", addr.size(),
                                 kMaxAddressLen);
    }
    reply_len_ = static_cast<uint8_t>(addr.size());
    for (std::size_t i = 0; i < addr.size(); ++i) {
      reply_[i] = addr[i];  // NOLINT
    }
    return *this;
  }

  constexpr auto SetTargetAddress(std::initializer_list<uint8_t> addr) noexcept
      -> TargetNode& {
    if (addr.size() > kMaxAddressLen) [[unlikely]] {
      detail::FailAddressTooLong("TargetNode target address", addr.size(),
                                 kMaxAddressLen);
    }
    target_len_ = static_cast<uint8_t>(addr.size());
    std::size_t i = 0;
    for (auto v : addr) {
      target_[i++] = v;  // NOLINT
    }
    return *this;
  }

  constexpr auto SetReplyAddress(std::initializer_list<uint8_t> addr) noexcept
      -> TargetNode& {
    if (addr.size() > kMaxAddressLen) [[unlikely]] {
      detail::FailAddressTooLong("TargetNode reply address", addr.size(),
                                 kMaxAddressLen);
    }
    reply_len_ = static_cast<uint8_t>(addr.size());
    std::size_t i = 0;
    for (auto v : addr) {
      reply_[i++] = v;  // NOLINT
    }
    return *this;
  }
};

}  // namespace spw_rmap
