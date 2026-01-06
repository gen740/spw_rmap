#include "spw_rmap/packet_parser.hh"

#include <utility>

#include "spw_rmap/crc.hh"
#include "spw_rmap/error_code.hh"
#include "spw_rmap/rmap_packet_type.hh"

namespace spw_rmap {

auto ParseReadPacket(Packet& packet,
                     const std::span<const uint8_t> data) noexcept
    -> std::expected<Packet, std::error_code> {
  if (data.size() < 4) {
    return std::unexpected(make_error_code(RMAPParseStatus::kIncompletePacket));
  }
  size_t head = 0;
  const auto instruction = data[2];
  const size_t reply_address_size =
      static_cast<size_t>(instruction & 0b00000011) * 4;
  if (data.size() != 16 + reply_address_size) {
    return std::unexpected(make_error_code(RMAPParseStatus::kIncompletePacket));
  }
  if (crc::CalcCrc(data.subspan(0, 16 + reply_address_size)) != 0x00) {
    return std::unexpected(make_error_code(RMAPParseStatus::kHeaderCrcError));
  }
  packet.target_logical_address = data[head++];
  if (data[head++] != 0x01) {
    return std::unexpected(
        make_error_code(RMAPParseStatus::kUnknownProtocolIdentifier));
  }
  packet.instruction = data[head++];
  packet.key = data[head++];

  auto reply_address_first_byte = head;
  auto reply_address_actual_size = reply_address_size;
  for (size_t i = 0; i < reply_address_size; ++i) {
    if (data[head++] == 0x00) {
      reply_address_first_byte = head;
      reply_address_actual_size--;
    } else {
      head += reply_address_actual_size - 1;
      break;
    }
  }
  packet.reply_address =
      data.subspan(reply_address_first_byte, reply_address_actual_size);

  packet.initiator_logical_address = data[head++];
  packet.transaction_id = 0;
  packet.transaction_id |= (data[head++] << 8);
  packet.transaction_id |= (data[head++] << 0);
  packet.extended_address = data[head++];
  packet.address = 0;
  packet.address |= (data[head++] << 24);
  packet.address |= (data[head++] << 16);
  packet.address |= (data[head++] << 8);
  packet.address |= (data[head++] << 0);
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
  if (data.size() < 12) {
    return std::unexpected(make_error_code(RMAPParseStatus::kIncompletePacket));
  }
  if (crc::CalcCrc(data.subspan(0, 12)) != 0x00) {
    return std::unexpected(make_error_code(RMAPParseStatus::kHeaderCrcError));
  }
  packet.initiator_logical_address = data[head++];
  if (data[head++] != 0x01) {
    return std::unexpected(
        make_error_code(RMAPParseStatus::kUnknownProtocolIdentifier));
  }
  packet.instruction = data[head++];
  packet.status = static_cast<PacketStatusCode>(data[head++]);
  packet.target_logical_address = data[head++];
  packet.transaction_id = 0;
  packet.transaction_id |= (data[head++] << 8);
  packet.transaction_id |= (data[head++] << 0);
  head++;  // Skip reserved byte
  packet.data_length = 0;
  packet.data_length |= (data[head++] << 16);
  packet.data_length |= (data[head++] << 8);
  packet.data_length |= (data[head++] << 0);
  if (data.size() != 12 + packet.data_length + 1) {
    return std::unexpected(make_error_code(RMAPParseStatus::kIncompletePacket));
  }
  if (crc::CalcCrc(data.subspan(12, packet.data_length + 1)) != 0x00) {
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
  if (data.size() < 4) {
    return std::unexpected(make_error_code(RMAPParseStatus::kIncompletePacket));
  }
  size_t head = 0;
  const auto instruction = data[2];
  const size_t reply_address_size =
      static_cast<size_t>(instruction & 0b00000011) * 4;
  if (data.size() <= 16 + reply_address_size) {
    return std::unexpected(make_error_code(RMAPParseStatus::kIncompletePacket));
  }
  if (crc::CalcCrc(data.subspan(0, 16 + reply_address_size)) != 0x00) {
    return std::unexpected(make_error_code(RMAPParseStatus::kHeaderCrcError));
  }
  packet.target_logical_address = data[head++];
  if (data[head++] != 0x01) {
    return std::unexpected(
        make_error_code(RMAPParseStatus::kUnknownProtocolIdentifier));
  }
  packet.instruction = data[head++];
  packet.key = data[head++];
  auto reply_address_first_byte = head;
  auto reply_address_actual_size = reply_address_size;
  for (size_t i = 0; i < reply_address_size; ++i) {
    if (data[head++] == 0x00) {
      reply_address_first_byte = head;
      reply_address_actual_size--;
    } else {
      head += reply_address_actual_size - 1;
      break;
    }
  }
  packet.reply_address =
      data.subspan(reply_address_first_byte, reply_address_actual_size);
  packet.initiator_logical_address = data[head++];
  packet.transaction_id = 0;
  packet.transaction_id |= (data[head++] << 8);
  packet.transaction_id |= (data[head++] << 0);
  packet.extended_address = data[head++];
  packet.address = 0;
  packet.address |= (data[head++] << 24);
  packet.address |= (data[head++] << 16);
  packet.address |= (data[head++] << 8);
  packet.address |= (data[head++] << 0);
  packet.data_length = 0;
  packet.data_length |= (data[head++] << 16);
  packet.data_length |= (data[head++] << 8);
  packet.data_length |= (data[head++] << 0);
  if (data.size() != 16 + reply_address_size + packet.data_length + 1) {
    return std::unexpected(make_error_code(RMAPParseStatus::kIncompletePacket));
  }
  if (crc::CalcCrc(data.subspan(16 + reply_address_size,
                                packet.data_length + 1)) != 0x00) {
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
  if (data.size() != 8) {
    return std::unexpected(make_error_code(RMAPParseStatus::kIncompletePacket));
  }
  if (crc::CalcCrc(data.subspan(0, 8)) != 0x00) {
    return std::unexpected(make_error_code(RMAPParseStatus::kHeaderCrcError));
  }
  packet.initiator_logical_address = data[head++];
  if (data[head++] != 0x01) {
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
  if (data.size() - head < 4) {
    return std::unexpected(make_error_code(RMAPParseStatus::kIncompletePacket));
  }
  packet.instruction = data[head + 2];
  bool is_command = (packet.instruction & 0b01000000) != 0;
  bool is_write =
      (packet.instruction & std::to_underlying(RMAPCommandCode::kWrite)) != 0;
  switch (is_command << 1 | is_write) {
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
