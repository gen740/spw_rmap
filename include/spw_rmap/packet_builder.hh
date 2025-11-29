// Copyright (c) 2025 Gen
// Licensed under the MIT License. See LICENSE file for details.
#pragma once

#include <cassert>
#include <cstdint>
#include <expected>
#include <span>
#include <system_error>

#include "spw_rmap/packet_parser.hh"

namespace spw_rmap {

struct ReadPacketConfig {
  std::span<const uint8_t> targetSpaceWireAddress;
  std::span<const uint8_t> replyAddress;
  uint8_t targetLogicalAddress{0};
  uint8_t initiatorLogicalAddress{0xFE};
  uint16_t transactionID{0};
  uint8_t extendedAddress{0};
  uint32_t address{0};
  uint32_t dataLength{0};
  uint8_t key{0};
  bool incrementMode{true};

  [[nodiscard]] auto expectedSize() const noexcept -> size_t {
    return targetSpaceWireAddress.size() + 4 +
           ((replyAddress.size() + 3) / 4 * 4) +  // Reply address
           12;
  }
};

struct WritePacketConfig {
  std::span<const uint8_t> targetSpaceWireAddress;
  std::span<const uint8_t> replyAddress;
  uint8_t targetLogicalAddress{0};
  uint8_t initiatorLogicalAddress{0xFE};
  uint16_t transactionID{0};
  uint8_t key{0};
  uint8_t extendedAddress{0};
  uint32_t address{0};
  bool incrementMode{true};
  bool reply{true};
  bool verifyMode{true};
  std::span<const uint8_t> data;

  [[nodiscard]] auto expectedSize() const noexcept -> size_t {
    return targetSpaceWireAddress.size() + 4 +
           ((replyAddress.size() + 3) / 4 * 4) + 12 + data.size() + 1;
  }
};

struct ReadReplyPacketConfig {
  std::span<const uint8_t> replyAddress;
  uint8_t initiatorLogicalAddress{0xFE};
  PacketStatusCode status{PacketStatusCode::CommandExecutedSuccessfully};
  uint8_t targetLogicalAddress{0};
  uint16_t transactionID{0};
  std::span<const uint8_t> data;
  bool incrementMode{true};

  [[nodiscard]] auto expectedSize() const noexcept -> size_t {
    return replyAddress.size() + 12 + data.size() + 1;
  }
};

struct WriteReplyPacketConfig {
  std::span<const uint8_t> replyAddress;
  uint8_t initiatorLogicalAddress{0xFE};
  PacketStatusCode status{PacketStatusCode::CommandExecutedSuccessfully};
  uint8_t targetLogicalAddress{0};
  uint16_t transactionID{0};
  bool incrementMode{true};
  bool verifyMode{true};

  [[nodiscard]] auto expectedSize() const noexcept -> size_t {
    return replyAddress.size() + 8;
  }
};

auto BuildReadPacket(const ReadPacketConfig& config,
                     std::span<uint8_t> out) noexcept
    -> std::expected<size_t, std::error_code>;

auto BuildWritePacket(const WritePacketConfig& config,
                      std::span<uint8_t> out) noexcept
    -> std::expected<size_t, std::error_code>;

auto BuildReadReplyPacket(const ReadReplyPacketConfig& config,
                          std::span<uint8_t> out) noexcept
    -> std::expected<size_t, std::error_code>;

auto BuildWriteReplyPacket(const WriteReplyPacketConfig& config,
                           std::span<uint8_t> out) noexcept
    -> std::expected<size_t, std::error_code>;

};  // namespace spw_rmap
