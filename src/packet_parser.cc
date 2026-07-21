#include "spw_rmap/packet_parser.hh"

#include <utility>

#include "spw_rmap/crc.hh"
#include "spw_rmap/error_code.hh"
#include "spw_rmap/rmap_packet_type.hh"

namespace spw_rmap {

namespace {

auto ReplySpwAddressFromField(
    std::span<const uint8_t> reply_address_field) noexcept
    -> std::span<const uint8_t> {
  size_t padding_size = 0;
  while (padding_size < reply_address_field.size() &&
         reply_address_field[padding_size] == 0x00) {
    ++padding_size;
  }
  // ECSS-E-ST-50-52C 5.1.6(d): a non-empty, all-zero Reply Address
  // represents the single-byte Reply SpaceWire Address {0x00}.
  if (padding_size == reply_address_field.size() && padding_size != 0) {
    --padding_size;
  }
  return reply_address_field.subspan(padding_size);
}

}  // namespace

auto ParseReadPacket(Packet& packet,
                     const std::span<const uint8_t> data) noexcept
    -> std::expected<Packet, std::error_code> {
  if (data.size() < 4) [[unlikely]] {
    return std::unexpected(make_error_code(RMAPParseStatus::kIncompletePacket));
  }
  size_t head = 0;
  const auto instruction = data[2];
  const size_t reply_address_size =
      static_cast<size_t>(instruction & 0b00000011) * 4;
  if (data.size() != 16 + reply_address_size) [[unlikely]] {
    return std::unexpected(make_error_code(RMAPParseStatus::kIncompletePacket));
  }
  if (crc::CalcCrc(data.subspan(0, 16 + reply_address_size)) != 0x00)
      [[unlikely]] {
    return std::unexpected(make_error_code(RMAPParseStatus::kHeaderCrcError));
  }
  packet.target_logical_address = data[head++];
  if (data[head++] != 0x01) [[unlikely]] {
    return std::unexpected(
        make_error_code(RMAPParseStatus::kUnknownProtocolIdentifier));
  }
  packet.instruction = data[head++];
  packet.key = data[head++];

  packet.reply_address =
      ReplySpwAddressFromField(data.subspan(head, reply_address_size));
  head += reply_address_size;

  packet.initiator_logical_address = data[head++];
  packet.transaction_id = 0;
  packet.transaction_id |= (data[head++] << 8);
  packet.transaction_id |= (data[head++] << 0);
  packet.extended_address = data[head++];
  packet.address = 0;
  packet.address |= (static_cast<uint32_t>(data[head++]) << 24);
  packet.address |= (static_cast<uint32_t>(data[head++]) << 16);
  packet.address |= (static_cast<uint32_t>(data[head++]) << 8);
  packet.address |= (static_cast<uint32_t>(data[head++]) << 0);
  packet.data_length = 0;
  packet.data_length |= (data[head++] << 16);
  packet.data_length |= (data[head++] << 8);
  packet.data_length |= (data[head++] << 0);
  return packet;
}

auto ParseReadReplyPacket(Packet& packet,
                          const std::span<const uint8_t> data) noexcept
    -> std::expected<Packet, std::error_code> {
  size_t head = 0;
  if (data.size() < 12) [[unlikely]] {
    return std::unexpected(make_error_code(RMAPParseStatus::kIncompletePacket));
  }
  if (crc::CalcCrc(data.subspan(0, 12)) != 0x00) [[unlikely]] {
    return std::unexpected(make_error_code(RMAPParseStatus::kHeaderCrcError));
  }
  packet.initiator_logical_address = data[head++];
  if (data[head++] != 0x01) [[unlikely]] {
    return std::unexpected(
        make_error_code(RMAPParseStatus::kUnknownProtocolIdentifier));
  }
  packet.instruction = data[head++];
  packet.status = static_cast<PacketStatusCode>(data[head++]);
  packet.target_logical_address = data[head++];
  packet.transaction_id = 0;
  packet.transaction_id |= (data[head++] << 8);
  packet.transaction_id |= (data[head++] << 0);
  if (data[head++] != 0x00) [[unlikely]] {
    return std::unexpected(make_error_code(RMAPParseStatus::kInvalidHeader));
  }
  packet.data_length = 0;
  packet.data_length |= (data[head++] << 16);
  packet.data_length |= (data[head++] << 8);
  packet.data_length |= (data[head++] << 0);
  if (data.size() != 12 + packet.data_length + 1) [[unlikely]] {
    return std::unexpected(make_error_code(RMAPParseStatus::kIncompletePacket));
  }
  if (crc::CalcCrc(data.subspan(12, packet.data_length + 1)) != 0x00)
      [[unlikely]] {
    return std::unexpected(make_error_code(RMAPParseStatus::kDataCrcError));
  }
  head++;
  packet.data =
      std::span<const uint8_t>(data).subspan(head, packet.data_length);
  return packet;
}

auto ParseWritePacket(Packet& packet,
                      const std::span<const uint8_t> data) noexcept
    -> std::expected<Packet, std::error_code> {
  if (data.size() < 4) [[unlikely]] {
    return std::unexpected(make_error_code(RMAPParseStatus::kIncompletePacket));
  }
  size_t head = 0;
  const auto instruction = data[2];
  const size_t reply_address_size =
      static_cast<size_t>(instruction & 0b00000011) * 4;
  if (data.size() <= 16 + reply_address_size) [[unlikely]] {
    return std::unexpected(make_error_code(RMAPParseStatus::kIncompletePacket));
  }
  if (crc::CalcCrc(data.subspan(0, 16 + reply_address_size)) != 0x00)
      [[unlikely]] {
    return std::unexpected(make_error_code(RMAPParseStatus::kHeaderCrcError));
  }
  packet.target_logical_address = data[head++];
  if (data[head++] != 0x01) [[unlikely]] {
    return std::unexpected(
        make_error_code(RMAPParseStatus::kUnknownProtocolIdentifier));
  }
  packet.instruction = data[head++];
  packet.key = data[head++];
  packet.reply_address =
      ReplySpwAddressFromField(data.subspan(head, reply_address_size));
  head += reply_address_size;
  packet.initiator_logical_address = data[head++];
  packet.transaction_id = 0;
  packet.transaction_id |= (data[head++] << 8);
  packet.transaction_id |= (data[head++] << 0);
  packet.extended_address = data[head++];
  packet.address = 0;
  packet.address |= (static_cast<uint32_t>(data[head++]) << 24);
  packet.address |= (static_cast<uint32_t>(data[head++]) << 16);
  packet.address |= (static_cast<uint32_t>(data[head++]) << 8);
  packet.address |= (static_cast<uint32_t>(data[head++]) << 0);
  packet.data_length = 0;
  packet.data_length |= (data[head++] << 16);
  packet.data_length |= (data[head++] << 8);
  packet.data_length |= (data[head++] << 0);
  if (data.size() != 16 + reply_address_size + packet.data_length + 1)
      [[unlikely]] {
    return std::unexpected(make_error_code(RMAPParseStatus::kIncompletePacket));
  }
  if (crc::CalcCrc(data.subspan(16 + reply_address_size,
                                packet.data_length + 1)) != 0x00) [[unlikely]] {
    return std::unexpected(make_error_code(RMAPParseStatus::kDataCrcError));
  }
  head++;  // Skip CRC byte
  packet.data =
      std::span<const uint8_t>(data).subspan(head, packet.data_length);
  return packet;
}

auto ParseWriteReplyPacket(Packet& packet,
                           const std::span<const uint8_t> data) noexcept
    -> std::expected<Packet, std::error_code> {
  size_t head = 0;
  if (data.size() != 8) [[unlikely]] {
    return std::unexpected(make_error_code(RMAPParseStatus::kIncompletePacket));
  }
  if (crc::CalcCrc(data.subspan(0, 8)) != 0x00) [[unlikely]] {
    return std::unexpected(make_error_code(RMAPParseStatus::kHeaderCrcError));
  }
  packet.initiator_logical_address = data[head++];
  if (data[head++] != 0x01) [[unlikely]] {
    return std::unexpected(
        make_error_code(RMAPParseStatus::kUnknownProtocolIdentifier));
  }
  packet.instruction = data[head++];
  packet.status = static_cast<PacketStatusCode>(data[head++]);
  packet.target_logical_address = data[head++];
  packet.transaction_id = 0;
  packet.transaction_id |= (data[head++] << 8);
  packet.transaction_id |= (data[head++] << 0);
  return packet;
}

auto ParseRMAPPacket(const std::span<const uint8_t> data) noexcept
    -> std::expected<Packet, std::error_code> {
  if (data.empty()) [[unlikely]] {
    return std::unexpected(make_error_code(RMAPParseStatus::kIncompletePacket));
  }
  Packet packet{};
  size_t head = 0;
  // Parse target SpaceWire address
  while (data[head] < 0x20) {
    head++;
    if (head >= data.size()) [[unlikely]] {
      return std::unexpected(
          make_error_code(RMAPParseStatus::kIncompletePacket));
    }
  }
  // Check size
  if (data.size() - head < 4) [[unlikely]] {
    return std::unexpected(make_error_code(RMAPParseStatus::kIncompletePacket));
  }
  packet.instruction = data[head + 2];
  const bool is_command =
      (packet.instruction & std::to_underlying(RMAPPacketType::kCommand)) != 0;
  const bool is_write =
      (packet.instruction & std::to_underlying(RMAPCommandCode::kWrite)) != 0;
  const bool verify =
      (packet.instruction &
       std::to_underlying(RMAPCommandCode::kVerifyDataBeforeWrite)) != 0;
  const bool reply =
      (packet.instruction & std::to_underlying(RMAPCommandCode::kReply)) != 0;

  // Bit 7 makes the two-bit Packet Type reserved. For non-write commands,
  // bit 4 distinguishes unsupported RMW from read, and read always replies.
  // A write reply can only correspond to a write that requested a reply.
  if ((packet.instruction & 0b10000000) != 0 ||
      (!is_write && (verify || !reply)) || (!is_command && is_write && !reply))
      [[unlikely]] {
    return std::unexpected(make_error_code(RMAPParseStatus::kInvalidHeader));
  }

  switch ((is_command << 1) | is_write) {
    case 0b00:  // Read reply
      packet.type = PacketType::kReadReply;
      packet.reply_spw_address =
          std::span<const uint8_t>(data).subspan(0, head);
      return ParseReadReplyPacket(packet, data.subspan(head));
    case 0b01:  // Write reply
      packet.type = PacketType::kWriteReply;
      packet.reply_spw_address =
          std::span<const uint8_t>(data).subspan(0, head);
      return ParseWriteReplyPacket(packet, data.subspan(head));
    case 0b10:  // Read command
      packet.type = PacketType::kRead;
      packet.target_spw_address =
          std::span<const uint8_t>(data).subspan(0, head);
      return ParseReadPacket(packet, data.subspan(head));
    case 0b11:  // Write command
      packet.type = PacketType::kWrite;
      packet.target_spw_address =
          std::span<const uint8_t>(data).subspan(0, head);
      return ParseWritePacket(packet, data.subspan(head));
    default:
      std::unreachable();
  }
}

}  // namespace spw_rmap
