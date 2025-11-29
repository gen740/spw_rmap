// Copyright (c) 2025 Gen
// Licensed under the MIT License. See LICENSE file for details.
#pragma once

#include <cstdint>
#include <expected>
#include <span>
#include <spw_rmap/error_code.hh>

namespace spw_rmap {

enum class PacketType {
  Undefined = 0,
  Read = 1,
  Write = 2,
  ReadReply = 3,
  WriteReply = 4,
};

enum class PacketStatusCode : uint8_t {
  CommandExecutedSuccessfully = 0,
  GeneralErrorCode = 1,
  UnusedRMAPPacketTypeOrCommandCode = 2,
  InvalidKey = 3,
  InvalidDataCRC = 4,
  EarlyEOP = 5,
  TooMuchData = 6,
  EEP = 7,
  VerifyBufferOverrun = 9,
  RMAPCommandNotImplementedOrNotAuthorised = 10,
  RMWDataLengthError = 11,
  InvalidTargetLogicalAddress = 12,
};

struct Packet {
  std::span<const uint8_t> targetSpaceWireAddress{};
  std::span<const uint8_t> replyAddress{};
  uint8_t initiatorLogicalAddress{};
  uint8_t instruction{};
  uint8_t key{};
  PacketStatusCode status{};
  uint8_t targetLogicalAddress{};
  uint16_t transactionID{};
  uint8_t extendedAddress{};
  uint32_t address{};
  uint32_t dataLength{};
  std::span<const uint8_t> data{};
  PacketType type{PacketType::Undefined};
};

auto ParseRMAPPacket(const std::span<const uint8_t> data) noexcept
    -> std::expected<Packet, std::error_code>;

};  // namespace spw_rmap
