// Copyright (c) 2025 Gen
// Licensed under the MIT License. See LICENSE file for details.
#pragma once

#include <cstdint>
#include <expected>
#include <span>
#include <system_error>

namespace spw_rmap {

enum class PacketType {
  kUndefined = 0,
  kRead = 1,
  kWrite = 2,
  kReadReply = 3,
  kWriteReply = 4,
};

enum class PacketStatusCode : uint8_t {
  kCommandExecutedSuccessfully = 0,
  kGeneralErrorCode = 1,
  kUnusedRmapPacketTypeOrCommandCode = 2,
  kInvalidKey = 3,
  kInvalidDataCrc = 4,
  kEarlyEop = 5,
  kTooMuchData = 6,
  kEep = 7,
  kVerifyBufferOverrun = 9,
  kRmapCommandNotImplementedOrNotAuthorised = 10,
  kRmwDataLengthError = 11,
  kInvalidTargetLogicalAddress = 12,
};

struct Packet {
  std::span<const uint8_t> target_spw_address{};
  std::span<const uint8_t> reply_address{};
  std::span<const uint8_t> reply_spw_address{};
  uint8_t initiator_logical_address{};
  uint8_t instruction{};
  uint8_t key{};
  PacketStatusCode status{};
  uint8_t target_logical_address{};
  uint16_t transaction_id{};
  uint8_t extended_address{};
  uint32_t address{};
  uint32_t data_length{};
  std::span<const uint8_t> data{};
  PacketType type{PacketType::kUndefined};
};

auto ParseRMAPPacket(const std::span<const uint8_t> data) noexcept
    -> std::expected<Packet, std::error_code>;

};  // namespace spw_rmap
