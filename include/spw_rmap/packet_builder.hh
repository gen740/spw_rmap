// Copyright (c) 2025 Gen
// Licensed under the MIT License. See LICENSE file for details.
#pragma once

#include <cstdint>
#include <expected>
#include <span>
#include <system_error>

#include "spw_rmap/packet_parser.hh"

namespace spw_rmap {

struct ReadPacketConfig {
  // Routing to target
  std::span<const uint8_t> target_spw_address;
  uint8_t target_logical_address{0};

  // Routing for reply
  std::span<const uint8_t> reply_address;
  uint8_t initiator_logical_address{0xFE};

  // Transaction / authorization
  uint16_t transaction_id{0};
  uint8_t key{0};

  // Remote memory location
  uint8_t extended_address{0};
  uint32_t address{0};
  uint32_t data_length{0};

  // Instruction options
  bool increment_mode{true};

  [[nodiscard]] auto ExpectedSize() const noexcept -> size_t {
    return target_spw_address.size() + 4 +
           ((reply_address.size() + 3) / 4 * 4) + 12;
  }
};

struct WritePacketConfig {
  // Routing to target
  std::span<const uint8_t> target_spw_address;
  uint8_t target_logical_address{0};

  // Routing for reply
  std::span<const uint8_t> reply_address;
  uint8_t initiator_logical_address{0xFE};

  // Transaction / authorization
  uint16_t transaction_id{0};
  uint8_t key{0};

  // Remote memory location
  uint8_t extended_address{0};
  uint32_t address{0};

  // Instruction options
  bool increment_mode{true};
  bool reply{true};
  bool verify_mode{true};

  // Data field
  std::span<const uint8_t> data;

  [[nodiscard]] auto ExpectedSize() const noexcept -> size_t {
    return target_spw_address.size() + 4 +
           ((reply_address.size() + 3) / 4 * 4) + 12 + data.size() + 1;
  }
};

struct ReadReplyPacketConfig {
  // Routing for reply
  std::span<const uint8_t> reply_spw_address;

  // Logical addressing
  uint8_t initiator_logical_address{0xFE};
  uint8_t target_logical_address{0};

  // Transaction identification
  uint16_t transaction_id{0};

  // Status
  PacketStatusCode status{PacketStatusCode::CommandExecutedSuccessfully};

  // Instruction option (copied from command)
  bool increment_mode{true};

  // Data field
  std::span<const uint8_t> data;

  [[nodiscard]] auto ExpectedSize() const noexcept -> size_t {
    return reply_spw_address.size() + 12 + data.size() + 1;
  }
};

struct WriteReplyPacketConfig {
  // Routing for reply
  std::span<const uint8_t> reply_spw_address;

  // Logical addressing
  uint8_t initiator_logical_address{0xFE};
  uint8_t target_logical_address{0};

  // Transaction identification
  uint16_t transaction_id{0};

  // Status
  PacketStatusCode status{PacketStatusCode::CommandExecutedSuccessfully};

  // Instruction options (copied from command)
  bool increment_mode{true};
  bool verify_mode{true};

  [[nodiscard]] auto ExpectedSize() const noexcept -> size_t {
    return reply_spw_address.size() + 8;
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
