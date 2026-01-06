// Copyright (c) 2025 Gen
// Licensed under the MIT License. See LICENSE file for details.
#pragma once

#include <array>
#include <cassert>
#include <cstdint>
#include <span>
#include <type_traits>

namespace spw_rmap {

class TargetNode {
 public:
  static constexpr std::size_t kMaxAddressLen = 12;

 private:
  uint8_t logical_address_{0xEF};
  std::array<uint8_t, kMaxAddressLen> target_{};
  std::array<uint8_t, kMaxAddressLen> reply_{};
  uint8_t target_len_{0};
  uint8_t reply_len_{0};

 public:
  [[nodiscard]] constexpr TargetNode() noexcept = default;

  [[nodiscard]] constexpr TargetNode(uint8_t logical_address = 0x00) noexcept
      : logical_address_(logical_address) {}

  [[nodiscard]] constexpr auto getTargetLogicalAddress() const noexcept
      -> uint8_t {
    return logical_address_;
  }

  [[nodiscard]] constexpr auto getTargetAddress() const noexcept
      -> std::span<const uint8_t> {
    return {target_.data(), target_len_};
  }

  [[nodiscard]] constexpr auto getReplyAddress() const noexcept
      -> std::span<const uint8_t> {
    return {reply_.data(), reply_len_};
  }

  constexpr auto setTargetLogicalAddress(uint8_t logical_address) noexcept
      -> TargetNode& {
    logical_address_ = logical_address;
    return *this;
  }

  template <class... Bs>
    requires(sizeof...(Bs) <= kMaxAddressLen &&
             (std::is_convertible_v<Bs, uint8_t> && ...))
  constexpr auto setTargetAddress(Bs... bs) noexcept -> TargetNode& {
    target_len_ = static_cast<uint8_t>(sizeof...(Bs));
    std::size_t i = 0;
    ((target_[i++] = static_cast<uint8_t>(bs)), ...);  // NOLINT
    return *this;
  }

  template <class... Bs>
    requires(sizeof...(Bs) <= kMaxAddressLen &&
             (std::is_convertible_v<Bs, uint8_t> && ...))
  constexpr auto setReplyAddress(Bs... bs) noexcept -> TargetNode& {
    reply_len_ = static_cast<uint8_t>(sizeof...(Bs));
    std::size_t i = 0;
    ((reply_[i++] = static_cast<uint8_t>(bs)), ...);  // NOLINT
    return *this;
  }

  constexpr auto setTargetAddress(std::span<const uint8_t> addr) noexcept
      -> TargetNode& {
    assert(addr.size() <= kMaxAddressLen);
    target_len_ = static_cast<uint8_t>(addr.size());
    for (std::size_t i = 0; i < addr.size(); ++i) {
      target_[i] = addr[i];  // NOLINT
    }
    return *this;
  }

  constexpr auto setReplyAddress(std::span<const uint8_t> addr) noexcept
      -> TargetNode& {
    assert(addr.size() <= kMaxAddressLen);
    reply_len_ = static_cast<uint8_t>(addr.size());
    for (std::size_t i = 0; i < addr.size(); ++i) {
      reply_[i] = addr[i];  // NOLINT
    }
    return *this;
  }

  constexpr auto setTargetAddress(std::initializer_list<uint8_t> addr) noexcept
      -> TargetNode& {
    assert(addr.size() <= kMaxAddressLen);
    target_len_ = static_cast<uint8_t>(addr.size());
    std::size_t i = 0;
    for (auto v : addr) {
      target_[i++] = v;  // NOLINT
    }
    return *this;
  }

  constexpr auto setReplyAddress(std::initializer_list<uint8_t> addr) noexcept
      -> TargetNode& {
    assert(addr.size() <= kMaxAddressLen);
    reply_len_ = static_cast<uint8_t>(addr.size());
    std::size_t i = 0;
    for (auto v : addr) {
      reply_[i++] = v;  // NOLINT
    }
    return *this;
  }
};

}  // namespace spw_rmap
