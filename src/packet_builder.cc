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
  if (out.size() < config.ExpectedSize()) [[unlikely]] {
    spw_rmap::debug::debug("ReadPacketBuilder::build: Buffer too small");
    return std::unexpected{std::make_error_code(std::errc::no_buffer_space)};
  }
  auto head = 0;
  for (const auto& byte : config.target_spw_address) {
    out[head++] = byte;
  }
  out[head++] = (config.target_logical_address);
  out[head++] = (RMAPProtocolIdentifier);
  auto reply_address_size = config.reply_address.size();
  uint8_t instruction = 0;
  instruction |= std::to_underlying(RMAPPacketType::Command);
  instruction |= std::to_underlying(RMAPCommandCode::Reply);
  if (config.increment_mode) {
    instruction |= std::to_underlying(RMAPCommandCode::IncrementAddress);
  }
  if (reply_address_size != 0) {
    assert(reply_address_size <= 12);
    reply_address_size = ((reply_address_size - 1) & 0x0C) + 0x04;
    instruction |= (reply_address_size >> 2);
  }
  out[head++] = (instruction);
  out[head++] = (config.key);
  if (reply_address_size != 0) {
    for (size_t i = 0; i < reply_address_size - config.reply_address.size();
         ++i) {
      out[head++] = (0x00);
    }
  }
  for (const auto& byte : config.reply_address) {
    out[head++] = (byte);
  }
  out[head++] = (config.initiator_logical_address);
  out[head++] = (static_cast<uint8_t>(config.transaction_id >> 8));
  out[head++] = (static_cast<uint8_t>(config.transaction_id & 0xFF));
  out[head++] = (config.extended_address);
  out[head++] = (static_cast<uint8_t>((config.address >> 24) & 0xFF));
  out[head++] = (static_cast<uint8_t>((config.address >> 16) & 0xFF));
  out[head++] = (static_cast<uint8_t>((config.address >> 8) & 0xFF));
  out[head++] = (static_cast<uint8_t>((config.address >> 0) & 0xFF));
  out[head++] = (static_cast<uint8_t>((config.data_length >> 16) & 0xFF));
  out[head++] = (static_cast<uint8_t>((config.data_length >> 8) & 0xFF));
  out[head++] = (static_cast<uint8_t>((config.data_length >> 0) & 0xFF));
  auto crc = crc::CalcCrc(
      std::span(out).subspan(config.target_spw_address.size(),
                             head - config.target_spw_address.size()));
  out[head++] = (crc);
  return head;
};

auto BuildWritePacket(const WritePacketConfig& config,
                      std::span<uint8_t> out) noexcept
    -> std::expected<size_t, std::error_code> {
  if (out.size() < config.ExpectedSize()) [[unlikely]] {
    spw_rmap::debug::debug("WritePacketBuilder::build: Buffer too small");
    return std::unexpected{std::make_error_code(std::errc::no_buffer_space)};
  }
  auto head = 0;
  for (const auto& byte : config.target_spw_address) {
    out[head++] = (byte);
  }
  out[head++] = (config.target_logical_address);
  out[head++] = (RMAPProtocolIdentifier);
  auto reply_address_size = config.reply_address.size();
  {  // Instruction field
    uint8_t instruction = 0;
    instruction |= std::to_underlying(RMAPPacketType::Command);
    instruction |= (std::to_underlying(RMAPCommandCode::Write));
    if (config.reply) {
      instruction |= std::to_underlying(RMAPCommandCode::Reply);
    }
    if (config.verify_mode) {
      instruction |= std::to_underlying(RMAPCommandCode::VerifyDataBeforeWrite);
    }
    if (config.increment_mode) {
      instruction |= std::to_underlying(RMAPCommandCode::IncrementAddress);
    }
    if (reply_address_size != 0) {
      assert(reply_address_size <= 12);
      reply_address_size =
          ((reply_address_size - 1) & 0x0C) + 0x04;  // Convert to 4-byte words
      instruction |= (reply_address_size >> 2);
    }
    out[head++] = (instruction);
  }
  out[head++] = (config.key);
  if (reply_address_size != 0) {
    for (size_t i = 0; i < reply_address_size - config.reply_address.size();
         ++i) {
      out[head++] = (0x00);
    }
  }
  for (const auto& byte : config.reply_address) {
    out[head++] = (byte);
  }
  out[head++] = (config.initiator_logical_address);
  out[head++] = (static_cast<uint8_t>(config.transaction_id >> 8));
  out[head++] = (static_cast<uint8_t>(config.transaction_id & 0xFF));
  out[head++] = (config.extended_address);
  out[head++] = (static_cast<uint8_t>((config.address >> 24) & 0xFF));
  out[head++] = (static_cast<uint8_t>((config.address >> 16) & 0xFF));
  out[head++] = (static_cast<uint8_t>((config.address >> 8) & 0xFF));
  out[head++] = (static_cast<uint8_t>((config.address >> 0) & 0xFF));

  auto dataLength = config.data.size();
  out[head++] = (static_cast<uint8_t>((dataLength >> 16) & 0xFF));
  out[head++] = (static_cast<uint8_t>((dataLength >> 8) & 0xFF));
  out[head++] = (static_cast<uint8_t>((dataLength >> 0) & 0xFF));

  auto crc = crc::CalcCrc(
      std::span(out).subspan(config.target_spw_address.size(),
                             head - config.target_spw_address.size()));
  out[head++] = (crc);

  // Append data
  for (const auto& byte : config.data) {
    out[head++] = (byte);
  }
  auto data_crc = crc::CalcCrc(std::span(config.data));
  out[head++] = (data_crc);
  return head;
};

auto BuildReadReplyPacket(const ReadReplyPacketConfig& config,
                          std::span<uint8_t> out) noexcept
    -> std::expected<size_t, std::error_code> {
  if (out.size() < config.ExpectedSize()) [[unlikely]] {
    spw_rmap::debug::debug("ReadReplyPacketBuilder::build: Buffer too small");
    return std::unexpected{std::make_error_code(std::errc::no_buffer_space)};
  }
  auto head = 0;
  for (const auto& byte : config.reply_spw_address) {
    out[head++] = (byte);
  }
  out[head++] = (config.initiator_logical_address);
  out[head++] = (RMAPProtocolIdentifier);
  {  // Instruction field
    uint8_t instruction = 0;
    instruction |= (std::to_underlying(RMAPPacketType::Reply));
    instruction |= std::to_underlying(RMAPCommandCode::Reply);
    if (config.increment_mode) {
      instruction |= std::to_underlying(RMAPCommandCode::IncrementAddress);
    }
    out[head++] = (instruction);
  }
  out[head++] = static_cast<uint8_t>(config.status);
  out[head++] = (config.target_logical_address);
  out[head++] = (static_cast<uint8_t>(config.transaction_id >> 8));
  out[head++] = (static_cast<uint8_t>(config.transaction_id & 0xFF));
  out[head++] = (0x00);  // Reserved byte
  auto dataLength = config.data.size();
  out[head++] = (static_cast<uint8_t>((dataLength >> 16) & 0xFF));
  out[head++] = (static_cast<uint8_t>((dataLength >> 8) & 0xFF));
  out[head++] = (static_cast<uint8_t>((dataLength >> 0) & 0xFF));
  auto crc = crc::CalcCrc(std::span(out).subspan(
      config.reply_spw_address.size(), head - config.reply_spw_address.size()));
  out[head++] = (crc);

  // Append data
  for (const auto& byte : config.data) {
    out[head++] = (byte);
  }
  auto data_crc = crc::CalcCrc(std::span(config.data));
  out[head++] = (data_crc);
  return head;
};

auto BuildWriteReplyPacket(const WriteReplyPacketConfig& config,
                           std::span<uint8_t> out) noexcept
    -> std::expected<size_t, std::error_code> {
  if (out.size() < config.ExpectedSize()) [[unlikely]] {
    spw_rmap::debug::debug("WriteReplyPacketBuilder::build: Buffer too small");
    return std::unexpected{std::make_error_code(std::errc::no_buffer_space)};
  }
  auto head = 0;
  for (const auto& byte : config.reply_spw_address) {
    out[head++] = (byte);
  }
  out[head++] = (config.initiator_logical_address);
  out[head++] = (0x01);  // Protocol Identifier
  {                      // Instruction field
    uint8_t instruction = 0;
    instruction |= (std::to_underlying(RMAPPacketType::Reply));
    instruction |= (std::to_underlying(RMAPCommandCode::Write));
    instruction |= std::to_underlying(RMAPCommandCode::Reply);
    if (config.verify_mode) {
      instruction |= std::to_underlying(RMAPCommandCode::VerifyDataBeforeWrite);
    }
    if (config.increment_mode) {
      instruction |= std::to_underlying(RMAPCommandCode::IncrementAddress);
    }
    out[head++] = (instruction);
  }
  out[head++] = static_cast<uint8_t>(config.status);
  out[head++] = (config.target_logical_address);
  out[head++] = (static_cast<uint8_t>(config.transaction_id >> 8));
  out[head++] = (static_cast<uint8_t>(config.transaction_id & 0xFF));
  auto crc = crc::CalcCrc(std::span(out).subspan(
      config.reply_spw_address.size(), head - config.reply_spw_address.size()));
  out[head++] = (crc);
  return head;
};

}  // namespace spw_rmap
