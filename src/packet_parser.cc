#include "spw_rmap/packet_parser.hh"

#include <utility>

#include "spw_rmap/crc.hh"
#include "spw_rmap/rmap_packet_type.hh"

namespace spw_rmap {

auto parseReadPacket_(Packet& packet,
                      const std::span<const uint8_t> data) noexcept
    -> std::expected<Packet, std::error_code> {
  if (data.size() < 4) {
    return std::unexpected(make_error_code(RMAPParseStatus::IncompletePacket));
  }
  size_t head = 0;
  const auto instruction = data[2];
  const size_t replyAddressSize =
      static_cast<size_t>(instruction & 0b00000011) * 4;
  if (data.size() != 16 + replyAddressSize) {
    return std::unexpected(make_error_code(RMAPParseStatus::IncompletePacket));
  }
  if (crc::calcCRC(data.subspan(0, 16 + replyAddressSize)) != 0x00) {
    return std::unexpected(make_error_code(RMAPParseStatus::HeaderCRCError));
  }
  packet.targetLogicalAddress = data[head++];
  if (data[head++] != 0x01) {
    return std::unexpected(
        make_error_code(RMAPParseStatus::UnknownProtocolIdentifier));
  }
  packet.instruction = data[head++];
  packet.key = data[head++];

  auto replyAddressFirstByte = head;
  auto replyAddressActualSize = replyAddressSize;
  for (size_t i = 0; i < replyAddressSize; ++i) {
    if (data[head++] == 0x00) {
      replyAddressFirstByte = head;
      replyAddressActualSize--;
    } else {
      head += replyAddressActualSize - 1;
      break;
    }
  }
  packet.replyAddress =
      data.subspan(replyAddressFirstByte, replyAddressActualSize);

  packet.initiatorLogicalAddress = data[head++];
  packet.transactionID = 0;
  packet.transactionID |= (data[head++] << 8);
  packet.transactionID |= (data[head++] << 0);
  packet.extendedAddress = data[head++];
  packet.address = 0;
  packet.address |= (data[head++] << 24);
  packet.address |= (data[head++] << 16);
  packet.address |= (data[head++] << 8);
  packet.address |= (data[head++] << 0);
  packet.dataLength = 0;
  packet.dataLength |= (data[head++] << 16);
  packet.dataLength |= (data[head++] << 8);
  packet.dataLength |= (data[head++] << 0);
  return packet;
}

auto parseReadReplyPacket_(Packet& packet,
                           const std::span<const uint8_t> data) noexcept
    -> std::expected<Packet, std::error_code> {
  size_t head = 0;
  if (data.size() < 12) {
    return std::unexpected(make_error_code(RMAPParseStatus::IncompletePacket));
  }
  if (crc::calcCRC(data.subspan(0, 12)) != 0x00) {
    return std::unexpected(make_error_code(RMAPParseStatus::HeaderCRCError));
  }
  packet.initiatorLogicalAddress = data[head++];
  if (data[head++] != 0x01) {
    return std::unexpected(
        make_error_code(RMAPParseStatus::UnknownProtocolIdentifier));
  }
  packet.instruction = data[head++];
  packet.status = static_cast<PacketStatusCode>(data[head++]);
  packet.targetLogicalAddress = data[head++];
  packet.transactionID = 0;
  packet.transactionID |= (data[head++] << 8);
  packet.transactionID |= (data[head++] << 0);
  head++;  // Skip reserved byte
  packet.dataLength = 0;
  packet.dataLength |= (data[head++] << 16);
  packet.dataLength |= (data[head++] << 8);
  packet.dataLength |= (data[head++] << 0);
  if (data.size() != 12 + packet.dataLength + 1) {
    return std::unexpected(make_error_code(RMAPParseStatus::IncompletePacket));
  }
  if (crc::calcCRC(data.subspan(12, packet.dataLength + 1)) != 0x00) {
    return std::unexpected(make_error_code(RMAPParseStatus::DataCRCError));
  }
  head++;
  packet.data = std::span<const uint8_t>(data).subspan(head, packet.dataLength);
  return packet;
}

auto parseWritePacket_(Packet& packet,
                       const std::span<const uint8_t> data) noexcept
    -> std::expected<Packet, std::error_code> {
  if (data.size() < 4) {
    return std::unexpected(make_error_code(RMAPParseStatus::IncompletePacket));
  }
  size_t head = 0;
  const auto instruction = data[2];
  const size_t replyAddressSize =
      static_cast<size_t>(instruction & 0b00000011) * 4;
  if (data.size() <= 16 + replyAddressSize) {
    return std::unexpected(make_error_code(RMAPParseStatus::IncompletePacket));
  }
  if (crc::calcCRC(data.subspan(0, 16 + replyAddressSize)) != 0x00) {
    return std::unexpected(make_error_code(RMAPParseStatus::HeaderCRCError));
  }
  packet.targetLogicalAddress = data[head++];
  if (data[head++] != 0x01) {
    return std::unexpected(
        make_error_code(RMAPParseStatus::UnknownProtocolIdentifier));
  }
  packet.instruction = data[head++];
  packet.key = data[head++];
  auto replyAddressFirstByte = head;
  auto replyAddressActualSize = replyAddressSize;
  for (size_t i = 0; i < replyAddressSize; ++i) {
    if (data[head++] == 0x00) {
      replyAddressFirstByte = head;
      replyAddressActualSize--;
    } else {
      head += replyAddressActualSize - 1;
      break;
    }
  }
  packet.replyAddress =
      data.subspan(replyAddressFirstByte, replyAddressActualSize);
  packet.initiatorLogicalAddress = data[head++];
  packet.transactionID = 0;
  packet.transactionID |= (data[head++] << 8);
  packet.transactionID |= (data[head++] << 0);
  packet.extendedAddress = data[head++];
  packet.address = 0;
  packet.address |= (data[head++] << 24);
  packet.address |= (data[head++] << 16);
  packet.address |= (data[head++] << 8);
  packet.address |= (data[head++] << 0);
  packet.dataLength = 0;
  packet.dataLength |= (data[head++] << 16);
  packet.dataLength |= (data[head++] << 8);
  packet.dataLength |= (data[head++] << 0);
  if (data.size() != 16 + replyAddressSize + packet.dataLength + 1) {
    return std::unexpected(make_error_code(RMAPParseStatus::IncompletePacket));
  }
  if (crc::calcCRC(
          data.subspan(16 + replyAddressSize, packet.dataLength + 1)) != 0x00) {
    return std::unexpected(make_error_code(RMAPParseStatus::DataCRCError));
  }
  head++;  // Skip CRC byte
  packet.data = std::span<const uint8_t>(data).subspan(head, packet.dataLength);
  return packet;
}

auto parseWriteReplyPacket_(Packet& packet,
                            const std::span<const uint8_t> data) noexcept
    -> std::expected<Packet, std::error_code> {
  size_t head = 0;
  if (data.size() != 8) {
    return std::unexpected(make_error_code(RMAPParseStatus::IncompletePacket));
  }
  if (crc::calcCRC(data.subspan(0, 8)) != 0x00) {
    return std::unexpected(make_error_code(RMAPParseStatus::HeaderCRCError));
  }
  packet.initiatorLogicalAddress = data[head++];
  if (data[head++] != 0x01) {
    return std::unexpected(
        make_error_code(RMAPParseStatus::UnknownProtocolIdentifier));
  }
  packet.instruction = data[head++];
  packet.status = static_cast<PacketStatusCode>(data[head++]);
  packet.targetLogicalAddress = data[head++];
  packet.transactionID = 0;
  packet.transactionID |= (data[head++] << 8);
  packet.transactionID |= (data[head++] << 0);
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
          make_error_code(RMAPParseStatus::IncompletePacket));
    }
  }
  // Check size
  if (data.size() - head < 4) {
    return std::unexpected(make_error_code(RMAPParseStatus::IncompletePacket));
  }
  packet.instruction = data[head + 2];
  bool is_command = (packet.instruction & 0b01000000) != 0;
  bool is_write =
      (packet.instruction & std::to_underlying(RMAPCommandCode::Write)) != 0;
  switch (is_command << 1 | is_write) {
    case 0b00:  // Read reply
      packet.type = PacketType::ReadReply;
      packet.replyAddress = std::span<const uint8_t>(data).subspan(0, head);
      return parseReadReplyPacket_(packet, data.subspan(head));
    case 0b01:  // Write reply
      packet.type = PacketType::WriteReply;
      packet.replyAddress = std::span<const uint8_t>(data).subspan(0, head);
      return parseWriteReplyPacket_(packet, data.subspan(head));
    case 0b10:  // Read command
      packet.type = PacketType::Read;
      packet.targetSpaceWireAddress =
          std::span<const uint8_t>(data).subspan(0, head);
      return parseReadPacket_(packet, data.subspan(head));
    case 0b11:  // Write command
      packet.type = PacketType::Write;
      packet.targetSpaceWireAddress =
          std::span<const uint8_t>(data).subspan(0, head);
      return parseWritePacket_(packet, data.subspan(head));
    default:
      std::unreachable();
  }
}

}  // namespace spw_rmap
