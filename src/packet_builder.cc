// Copyright (c) 2025 Gen
// Licensed under the MIT License. See LICENSE file for details.
#include "spw_rmap/packet_builder.hh"

#include <cassert>
#include <utility>

#include "spw_rmap/crc.hh"
#include "spw_rmap/internal/debug.hh"
#include "spw_rmap/rmap_packet_type.hh"

namespace spw_rmap {

auto BuildReadPacket(const ReadPacketConfig& config,
                     std::span<uint8_t> out) noexcept
    -> std::expected<size_t, std::error_code> {
  if (out.size() < config.expectedSize()) [[unlikely]] {
    spw_rmap::debug::debug("ReadPacketBuilder::build: Buffer too small");
    return std::unexpected{std::make_error_code(std::errc::no_buffer_space)};
  }
  auto head = 0;
  for (const auto& byte : config.targetSpaceWireAddress) {
    out[head++] = byte;
  }
  out[head++] = (config.targetLogicalAddress);
  out[head++] = (RMAPProtocolIdentifier);
  auto replyAddressSize = config.replyAddress.size();
  uint8_t instruction = 0;
  instruction |= std::to_underlying(RMAPPacketType::Command);
  instruction |= std::to_underlying(RMAPCommandCode::Reply);
  if (config.incrementMode) {
    instruction |= std::to_underlying(RMAPCommandCode::IncrementAddress);
  }
  if (replyAddressSize != 0) {
    assert(replyAddressSize <= 12);
    replyAddressSize = ((replyAddressSize - 1) & 0x0C) + 0x04;
    instruction |= (replyAddressSize >> 2);
  }
  out[head++] = (instruction);
  out[head++] = (config.key);
  if (replyAddressSize != 0) {
    for (size_t i = 0; i < replyAddressSize - config.replyAddress.size(); ++i) {
      out[head++] = (0x00);
    }
  }
  for (const auto& byte : config.replyAddress) {
    out[head++] = (byte);
  }
  out[head++] = (config.initiatorLogicalAddress);
  out[head++] = (static_cast<uint8_t>(config.transactionID >> 8));
  out[head++] = (static_cast<uint8_t>(config.transactionID & 0xFF));
  out[head++] = (config.extendedAddress);
  out[head++] = (static_cast<uint8_t>((config.address >> 24) & 0xFF));
  out[head++] = (static_cast<uint8_t>((config.address >> 16) & 0xFF));
  out[head++] = (static_cast<uint8_t>((config.address >> 8) & 0xFF));
  out[head++] = (static_cast<uint8_t>((config.address >> 0) & 0xFF));
  out[head++] = (static_cast<uint8_t>((config.dataLength >> 16) & 0xFF));
  out[head++] = (static_cast<uint8_t>((config.dataLength >> 8) & 0xFF));
  out[head++] = (static_cast<uint8_t>((config.dataLength >> 0) & 0xFF));
  auto crc = crc::calcCRC(
      std::span(out).subspan(config.targetSpaceWireAddress.size(),
                             head - config.targetSpaceWireAddress.size()));
  out[head++] = (crc);
  return head;
};

auto BuildWritePacket(const WritePacketConfig& config,
                      std::span<uint8_t> out) noexcept
    -> std::expected<size_t, std::error_code> {
  if (out.size() < config.expectedSize()) [[unlikely]] {
    spw_rmap::debug::debug("WritePacketBuilder::build: Buffer too small");
    return std::unexpected{std::make_error_code(std::errc::no_buffer_space)};
  }
  auto head = 0;
  for (const auto& byte : config.targetSpaceWireAddress) {
    out[head++] = (byte);
  }
  out[head++] = (config.targetLogicalAddress);
  out[head++] = (RMAPProtocolIdentifier);
  auto replyAddressSize = config.replyAddress.size();
  {  // Instruction field
    uint8_t instruction = 0;
    instruction |= std::to_underlying(RMAPPacketType::Command);
    instruction |= (std::to_underlying(RMAPCommandCode::Write));
    if (config.reply) {
      instruction |= std::to_underlying(RMAPCommandCode::Reply);
    }
    if (config.verifyMode) {
      instruction |= std::to_underlying(RMAPCommandCode::VerifyDataBeforeWrite);
    }
    if (config.incrementMode) {
      instruction |= std::to_underlying(RMAPCommandCode::IncrementAddress);
    }
    if (replyAddressSize != 0) {
      assert(replyAddressSize <= 12);
      replyAddressSize =
          ((replyAddressSize - 1) & 0x0C) + 0x04;  // Convert to 4-byte words
      instruction |= (replyAddressSize >> 2);
    }
    out[head++] = (instruction);
  }
  out[head++] = (config.key);
  if (replyAddressSize != 0) {
    for (size_t i = 0; i < replyAddressSize - config.replyAddress.size(); ++i) {
      out[head++] = (0x00);
    }
  }
  for (const auto& byte : config.replyAddress) {
    out[head++] = (byte);
  }
  out[head++] = (config.initiatorLogicalAddress);
  out[head++] = (static_cast<uint8_t>(config.transactionID >> 8));
  out[head++] = (static_cast<uint8_t>(config.transactionID & 0xFF));
  out[head++] = (config.extendedAddress);
  out[head++] = (static_cast<uint8_t>((config.address >> 24) & 0xFF));
  out[head++] = (static_cast<uint8_t>((config.address >> 16) & 0xFF));
  out[head++] = (static_cast<uint8_t>((config.address >> 8) & 0xFF));
  out[head++] = (static_cast<uint8_t>((config.address >> 0) & 0xFF));

  auto dataLength = config.data.size();
  out[head++] = (static_cast<uint8_t>((dataLength >> 16) & 0xFF));
  out[head++] = (static_cast<uint8_t>((dataLength >> 8) & 0xFF));
  out[head++] = (static_cast<uint8_t>((dataLength >> 0) & 0xFF));

  auto crc = crc::calcCRC(
      std::span(out).subspan(config.targetSpaceWireAddress.size(),
                             head - config.targetSpaceWireAddress.size()));
  out[head++] = (crc);

  // Append data
  for (const auto& byte : config.data) {
    out[head++] = (byte);
  }
  auto data_crc = crc::calcCRC(std::span(config.data));
  out[head++] = (data_crc);
  return head;
};

auto BuildReadReplyPacket(const ReadReplyPacketConfig& config,
                          std::span<uint8_t> out) noexcept
    -> std::expected<size_t, std::error_code> {
  if (out.size() < config.expectedSize()) [[unlikely]] {
    spw_rmap::debug::debug("ReadReplyPacketBuilder::build: Buffer too small");
    return std::unexpected{std::make_error_code(std::errc::no_buffer_space)};
  }
  auto head = 0;
  for (const auto& byte : config.replyAddress) {
    out[head++] = (byte);
  }
  out[head++] = (config.initiatorLogicalAddress);
  out[head++] = (RMAPProtocolIdentifier);
  {  // Instruction field
    uint8_t instruction = 0;
    instruction |= (std::to_underlying(RMAPPacketType::Reply));
    instruction |= std::to_underlying(RMAPCommandCode::Reply);
    if (config.incrementMode) {
      instruction |= std::to_underlying(RMAPCommandCode::IncrementAddress);
    }
    out[head++] = (instruction);
  }
  out[head++] = static_cast<uint8_t>(config.status);
  out[head++] = (config.targetLogicalAddress);
  out[head++] = (static_cast<uint8_t>(config.transactionID >> 8));
  out[head++] = (static_cast<uint8_t>(config.transactionID & 0xFF));
  out[head++] = (0x00);  // Reserved byte
  auto dataLength = config.data.size();
  out[head++] = (static_cast<uint8_t>((dataLength >> 16) & 0xFF));
  out[head++] = (static_cast<uint8_t>((dataLength >> 8) & 0xFF));
  out[head++] = (static_cast<uint8_t>((dataLength >> 0) & 0xFF));
  auto crc = crc::calcCRC(std::span(out).subspan(
      config.replyAddress.size(), head - config.replyAddress.size()));
  out[head++] = (crc);

  // Append data
  for (const auto& byte : config.data) {
    out[head++] = (byte);
  }
  auto data_crc = crc::calcCRC(std::span(config.data));
  out[head++] = (data_crc);
  return head;
};

auto BuildWriteReplyPacket(const WriteReplyPacketConfig& config,
                           std::span<uint8_t> out) noexcept
    -> std::expected<size_t, std::error_code> {
  if (out.size() < config.expectedSize()) [[unlikely]] {
    spw_rmap::debug::debug("WriteReplyPacketBuilder::build: Buffer too small");
    return std::unexpected{std::make_error_code(std::errc::no_buffer_space)};
  }
  auto head = 0;
  for (const auto& byte : config.replyAddress) {
    out[head++] = (byte);
  }
  out[head++] = (config.initiatorLogicalAddress);
  out[head++] = (0x01);  // Protocol Identifier
  {                      // Instruction field
    uint8_t instruction = 0;
    instruction |= (std::to_underlying(RMAPPacketType::Reply));
    instruction |= (std::to_underlying(RMAPCommandCode::Write));
    instruction |= std::to_underlying(RMAPCommandCode::Reply);
    if (config.verifyMode) {
      instruction |= std::to_underlying(RMAPCommandCode::VerifyDataBeforeWrite);
    }
    if (config.incrementMode) {
      instruction |= std::to_underlying(RMAPCommandCode::IncrementAddress);
    }
    out[head++] = (instruction);
  }
  out[head++] = static_cast<uint8_t>(config.status);
  out[head++] = (config.targetLogicalAddress);
  out[head++] = (static_cast<uint8_t>(config.transactionID >> 8));
  out[head++] = (static_cast<uint8_t>(config.transactionID & 0xFF));
  auto crc = crc::calcCRC(std::span(out).subspan(
      config.replyAddress.size(), head - config.replyAddress.size()));
  out[head++] = (crc);
  return head;
};

}  // namespace spw_rmap
