#include <gmock/gmock.h>
#include <gtest/gtest-matchers.h>
#include <gtest/gtest.h>

#include <random>
#include <spw_rmap/error_code.hh>
#include <spw_rmap/packet_builder.hh>
#include <spw_rmap/packet_parser.hh>
#include <system_error>

#include "spw_rmap/crc.hh"
#include "spw_rmap/target_node.hh"

auto RandomLogicalAddress() {
  static std::random_device rd;
  static std::mt19937 gen(rd());
  return std::uniform_int_distribution<uint8_t>(32, 126)(gen);
}

auto RandomBusAddress() {
  static std::random_device rd;
  static std::mt19937 gen(rd());
  return std::uniform_int_distribution<uint8_t>(1, 31)(gen);
}

auto RandomAddress() {
  static std::random_device rd;
  static std::mt19937 gen(rd());
  return std::uniform_int_distribution<uint32_t>(0, 0xFFFFFFFF)(gen);
}

auto RandomDataLength() {
  static std::random_device rd;
  static std::mt19937 gen(rd());
  return std::uniform_int_distribution<uint16_t>(1, 1024)(gen);
}

auto RandomByte() {
  static std::random_device rd;
  static std::mt19937 gen(rd());
  return std::uniform_int_distribution<uint8_t>(0, 255)(gen);
}

auto RandomBusLength() {
  static std::random_device rd;
  static std::mt19937 gen(rd());
  return std::uniform_int_distribution<size_t>(0, 12)(gen);
}

using ::testing::Eq;
using ::testing::Pointwise;

template <class T>
auto SpanEqual(std::span<const T> a, std::span<const T> b)
    -> ::testing::AssertionResult {
  if (a.size() != b.size()) {
    return ::testing::AssertionFailure()
           << "size mismatch: " << a.size() << " vs " << b.size();
  }
  for (size_t i = 0; i < a.size(); ++i) {
    if (a[i] != b[i]) {
      return ::testing::AssertionFailure()
             << "mismatch at " << i << ": " << +a[i] << " vs " << +b[i];
    }
  }
  return ::testing::AssertionSuccess();
}

auto RecalculateHeaderCrc(std::vector<uint8_t>& packet,
                          std::size_t header_start, std::size_t crc_index)
    -> void {
  packet[crc_index] =
      spw_rmap::crc::CalcCrc(std::span<const uint8_t>(packet).subspan(
          header_start, crc_index - header_start));
}

TEST(spw_rmap, ReadPacket) {
  using namespace spw_rmap;

  for (int i = 0; i < 1000; ++i) {
    std::vector<uint8_t> target_address;
    std::vector<uint8_t> reply_address;

    for (size_t i = 0; i < RandomBusLength(); ++i) {
      target_address.push_back(RandomBusAddress());
      reply_address.push_back(RandomBusAddress());
    }

    TargetNode node(RandomLogicalAddress());
    std::ignore = node.SetTargetAddress(target_address);
    std::ignore = node.SetReplyAddress(reply_address);

    auto c = ReadPacketConfig{
        .target_spw_address = node.GetTargetAddress(),
        .target_logical_address = node.GetTargetLogicalAddress(),
        .reply_address = node.GetReplyAddress(),
        .initiator_logical_address = RandomLogicalAddress(),
        .transaction_id =
            static_cast<uint16_t>(RandomByte() << 8 | RandomByte()),
        .key = RandomByte(),
        .extended_address = RandomByte(),
        .address = RandomAddress(),
        .data_length = RandomDataLength(),
        .increment_mode = RandomByte() % 2 == 0,
    };

    std::vector<uint8_t> packet;
    packet.resize(c.ExpectedSize());

    auto res = spw_rmap::BuildReadPacket(c, packet);
    ASSERT_TRUE(res.has_value());
    auto parsed = ParseRMAPPacket(packet);
    ASSERT_TRUE(parsed.has_value());

    auto d = parsed.value();
    EXPECT_TRUE(SpanEqual(d.target_spw_address, c.target_spw_address));
    EXPECT_TRUE(SpanEqual(d.reply_address, c.reply_address));
    EXPECT_EQ(d.target_logical_address, c.target_logical_address);
    EXPECT_EQ(d.initiator_logical_address, c.initiator_logical_address);
    EXPECT_EQ(d.transaction_id, c.transaction_id);
    EXPECT_EQ(d.extended_address, c.extended_address);
    EXPECT_EQ(d.address, c.address);
    EXPECT_EQ(d.data_length, c.data_length);
    EXPECT_EQ(d.key, c.key);
    EXPECT_EQ(d.type, PacketType::kRead);
    EXPECT_EQ(d.instruction & 0b00000100, c.increment_mode ? 0b00000100 : 0);
  }
}

TEST(spw_rmap, ReadReplyPacket) {
  using namespace spw_rmap;

  for (int i = 0; i < 1000; ++i) {
    std::vector<uint8_t> target_address;
    std::vector<uint8_t> reply_address;

    for (size_t i = 0; i < RandomBusLength(); ++i) {
      target_address.push_back(RandomBusAddress());
      reply_address.push_back(RandomBusAddress());
    }

    TargetNode node(RandomLogicalAddress());
    std::ignore = node.SetTargetAddress(target_address);
    std::ignore = node.SetReplyAddress(reply_address);

    std::vector<uint8_t> data;

    for (size_t i = 0; i < RandomDataLength(); ++i) {
      data.push_back(RandomByte());
    }

    auto c = ReadReplyPacketConfig{
        .reply_spw_address = node.GetReplyAddress(),
        .target_logical_address = node.GetTargetLogicalAddress(),
        .transaction_id =
            static_cast<uint16_t>(RandomByte() << 8 | RandomByte()),
        .status = static_cast<PacketStatusCode>(RandomByte()),
        .reply_address_length =
            static_cast<uint8_t>((reply_address.size() + 3) / 4),
        .increment_mode = RandomByte() % 2 == 0,
        .data = data,
    };
    if (c.status != PacketStatusCode::kCommandExecutedSuccessfully) {
      c.data = {};
    }

    std::vector<uint8_t> packet;
    packet.resize(c.ExpectedSize());

    auto res = spw_rmap::BuildReadReplyPacket(c, packet);
    ASSERT_TRUE(res.has_value());
    auto parsed = ParseRMAPPacket(packet);
    ASSERT_TRUE(parsed.has_value());

    auto d = parsed.value();
    EXPECT_TRUE(SpanEqual(d.reply_spw_address, c.reply_spw_address));
    EXPECT_EQ(d.status, c.status);
    EXPECT_EQ(d.target_logical_address, c.target_logical_address);
    EXPECT_EQ(d.transaction_id, c.transaction_id);
    EXPECT_TRUE(SpanEqual(d.data, c.data));
    EXPECT_EQ(d.type, PacketType::kReadReply);
    EXPECT_EQ(d.instruction & 0b00000100, c.increment_mode ? 0b00000100 : 0);
    EXPECT_EQ(d.instruction & 0b00000011, c.reply_address_length);
  }
}

TEST(spw_rmap, WritePacket) {
  using namespace spw_rmap;

  for (int i = 0; i < 1000; ++i) {
    std::vector<uint8_t> target_address;
    std::vector<uint8_t> reply_address;

    for (size_t i = 0; i < RandomBusLength(); ++i) {
      target_address.push_back(RandomBusAddress());
      reply_address.push_back(RandomBusAddress());
    }

    TargetNode node(RandomLogicalAddress());
    std::ignore = node.SetTargetAddress(target_address);
    std::ignore = node.SetReplyAddress(reply_address);

    std::vector<uint8_t> data;

    for (size_t i = 0; i < RandomDataLength(); ++i) {
      data.push_back(RandomByte());
    }

    auto c = WritePacketConfig{
        .target_spw_address = node.GetTargetAddress(),
        .target_logical_address = node.GetTargetLogicalAddress(),
        .reply_address = node.GetReplyAddress(),
        .initiator_logical_address = RandomLogicalAddress(),
        .transaction_id =
            static_cast<uint16_t>(RandomByte() << 8 | RandomByte()),
        .key = RandomByte(),
        .extended_address = RandomByte(),
        .address = RandomAddress(),
        .increment_mode = RandomByte() % 2 == 0,
        .verify_mode = RandomByte() % 2 == 0,
        .data = data,
    };

    std::vector<uint8_t> packet;
    packet.resize(c.ExpectedSize());

    auto res = spw_rmap::BuildWritePacket(c, packet);
    ASSERT_TRUE(res.has_value());
    auto parsed = ParseRMAPPacket(packet);
    ASSERT_TRUE(parsed.has_value());

    auto d = parsed.value();
    EXPECT_TRUE(SpanEqual(d.target_spw_address, c.target_spw_address));
    EXPECT_TRUE(SpanEqual(d.reply_address, c.reply_address));
    EXPECT_EQ(d.target_logical_address, c.target_logical_address);
    EXPECT_EQ(d.initiator_logical_address, c.initiator_logical_address);
    EXPECT_EQ(d.transaction_id, c.transaction_id);
    EXPECT_EQ(d.key, c.key);
    EXPECT_EQ(d.extended_address, c.extended_address);
    EXPECT_EQ(d.address, c.address);
    EXPECT_EQ(d.instruction & 0b00000100, c.increment_mode ? 0b00000100 : 0);
    EXPECT_TRUE(SpanEqual(d.data, c.data));
  }
}

TEST(spw_rmap, WriteReplyPacket) {
  using namespace spw_rmap;

  for (int i = 0; i < 1000; ++i) {
    std::vector<uint8_t> target_address;
    std::vector<uint8_t> reply_address;

    for (size_t i = 0; i < RandomBusLength(); ++i) {
      target_address.push_back(RandomBusAddress());
      reply_address.push_back(RandomBusAddress());
    }

    TargetNode node(RandomLogicalAddress());
    std::ignore = node.SetTargetAddress(target_address);
    std::ignore = node.SetReplyAddress(reply_address);

    auto c = WriteReplyPacketConfig{
        .reply_spw_address = node.GetReplyAddress(),
        .initiator_logical_address = RandomLogicalAddress(),
        .target_logical_address = node.GetTargetLogicalAddress(),
        .transaction_id =
            static_cast<uint16_t>(RandomByte() << 8 | RandomByte()),
        .status = static_cast<PacketStatusCode>(RandomByte()),
        .reply_address_length =
            static_cast<uint8_t>((reply_address.size() + 3) / 4),
        .increment_mode = RandomByte() % 2 == 0,
        .verify_mode = RandomByte() % 2 == 0,
    };

    std::vector<uint8_t> packet;
    packet.resize(c.ExpectedSize());

    auto res = spw_rmap::BuildWriteReplyPacket(c, packet);
    ASSERT_TRUE(res.has_value());
    auto parsed = ParseRMAPPacket(packet);
    ASSERT_TRUE(parsed.has_value());

    auto d = parsed.value();
    EXPECT_TRUE(SpanEqual(d.reply_spw_address, c.reply_spw_address));
    EXPECT_EQ(d.initiator_logical_address, c.initiator_logical_address);
    EXPECT_EQ(d.status, c.status);
    EXPECT_EQ(d.target_logical_address, c.target_logical_address);
    EXPECT_EQ(d.transaction_id, c.transaction_id);
    EXPECT_EQ(d.type, PacketType::kWriteReply);
    EXPECT_EQ(d.instruction & 0b00000100, c.increment_mode ? 0b00000100 : 0);
    EXPECT_EQ(d.instruction & 0b00000011, c.reply_address_length);
  }
}

TEST(spw_rmap, ParserRejectsEmptyAndTruncatedPackets) {
  using namespace spw_rmap;

  auto empty = ParseRMAPPacket({});
  ASSERT_FALSE(empty.has_value());
  EXPECT_EQ(empty.error(), make_error_code(RMAPParseStatus::kIncompletePacket));

  std::array<uint8_t, 1> reply_address{0x01};
  auto config = WriteReplyPacketConfig{
      .reply_spw_address = reply_address,
      .initiator_logical_address = 0xFE,
      .target_logical_address = 0x34,
      .transaction_id = 0x1234,
  };
  std::vector<uint8_t> packet(config.ExpectedSize());
  ASSERT_TRUE(BuildWriteReplyPacket(config, packet).has_value());

  for (std::size_t size = 0; size < packet.size(); ++size) {
    auto result = ParseRMAPPacket(std::span(packet).first(size));
    EXPECT_FALSE(result.has_value()) << "accepted prefix of size " << size;
  }
}

TEST(spw_rmap, ParserRejectsCorruptedHeaderCrc) {
  using namespace spw_rmap;

  std::array<uint8_t, 1> reply_address{0x01};
  auto config = WriteReplyPacketConfig{
      .reply_spw_address = reply_address,
      .initiator_logical_address = 0xFE,
      .target_logical_address = 0x34,
      .transaction_id = 0x1234,
  };
  std::vector<uint8_t> packet(config.ExpectedSize());
  ASSERT_TRUE(BuildWriteReplyPacket(config, packet).has_value());
  packet[reply_address.size() + 3] ^= 0x01;

  auto result = ParseRMAPPacket(packet);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), make_error_code(RMAPParseStatus::kHeaderCrcError));
}

TEST(spw_rmap, ParserRejectsCorruptedDataCrc) {
  using namespace spw_rmap;

  std::array<uint8_t, 1> reply_address{0x01};
  std::array<uint8_t, 4> data{0x12, 0x34, 0x56, 0x78};
  auto config = ReadReplyPacketConfig{
      .reply_spw_address = reply_address,
      .initiator_logical_address = 0xFE,
      .target_logical_address = 0x34,
      .transaction_id = 0x1234,
      .data = data,
  };
  std::vector<uint8_t> packet(config.ExpectedSize());
  ASSERT_TRUE(BuildReadReplyPacket(config, packet).has_value());
  packet.back() ^= 0x01;

  auto result = ParseRMAPPacket(packet);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), make_error_code(RMAPParseStatus::kDataCrcError));
}

TEST(spw_rmap, ParserRoundTripsMaximumAddress) {
  using namespace spw_rmap;

  auto config = ReadPacketConfig{};
  config.target_logical_address = 0x34;
  config.initiator_logical_address = 0xFE;
  config.transaction_id = 0xFFFF;
  config.address = 0xFFFF'FFFFU;
  config.data_length = 0x00FF'FFFFU;
  std::vector<uint8_t> packet(config.ExpectedSize());
  ASSERT_TRUE(BuildReadPacket(config, packet).has_value());

  auto result = ParseRMAPPacket(packet);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->address, config.address);
  EXPECT_EQ(result->data_length, config.data_length);
}

TEST(spw_rmap, BuildersRejectUndersizedOutputBuffers) {
  using namespace spw_rmap;

  std::array<uint8_t, 2> data{0x12, 0x34};
  auto read = ReadPacketConfig{};
  auto write = WritePacketConfig{};
  write.data = data;
  auto read_reply = ReadReplyPacketConfig{};
  read_reply.data = data;
  auto write_reply = WriteReplyPacketConfig{};

  const auto expect_no_space = [](auto config, auto builder) {
    std::vector<uint8_t> output(config.ExpectedSize() - 1);
    auto result = builder(config, output);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), std::make_error_code(std::errc::no_buffer_space));
  };

  expect_no_space(read, BuildReadPacket);
  expect_no_space(write, BuildWritePacket);
  expect_no_space(read_reply, BuildReadReplyPacket);
  expect_no_space(write_reply, BuildWriteReplyPacket);
}

TEST(spw_rmap, CommandBuildersRejectUnencodableFields) {
  using namespace spw_rmap;

  std::array<uint8_t, 13> oversized_reply_address{};
  auto read = ReadPacketConfig{};
  read.reply_address = oversized_reply_address;
  std::vector<uint8_t> read_output(read.ExpectedSize());
  auto read_result = BuildReadPacket(read, read_output);
  ASSERT_FALSE(read_result.has_value());
  EXPECT_EQ(read_result.error(),
            std::make_error_code(std::errc::invalid_argument));

  auto write = WritePacketConfig{};
  write.reply_address = oversized_reply_address;
  std::vector<uint8_t> write_output(write.ExpectedSize());
  auto write_result = BuildWritePacket(write, write_output);
  ASSERT_FALSE(write_result.has_value());
  EXPECT_EQ(write_result.error(),
            std::make_error_code(std::errc::invalid_argument));

  auto excessive_length = ReadPacketConfig{};
  excessive_length.data_length = 0x0100'0000U;
  std::vector<uint8_t> length_output(excessive_length.ExpectedSize());
  auto length_result = BuildReadPacket(excessive_length, length_output);
  ASSERT_FALSE(length_result.has_value());
  EXPECT_EQ(length_result.error(),
            std::make_error_code(std::errc::invalid_argument));
}

TEST(spw_rmap, BuildersRejectInvalidPathAndLogicalAddresses) {
  using namespace spw_rmap;

  const std::array<uint8_t, 1> invalid_path{0x20};
  auto read = ReadPacketConfig{};
  read.target_spw_address = invalid_path;
  read.target_logical_address = 0x34;
  std::vector<uint8_t> read_output(read.ExpectedSize());
  auto read_result = BuildReadPacket(read, read_output);
  ASSERT_FALSE(read_result.has_value());
  EXPECT_EQ(read_result.error(),
            std::make_error_code(std::errc::invalid_argument));

  auto write = WritePacketConfig{};
  write.target_logical_address = 0x1F;
  std::vector<uint8_t> write_output(write.ExpectedSize());
  auto write_result = BuildWritePacket(write, write_output);
  ASSERT_FALSE(write_result.has_value());
  EXPECT_EQ(write_result.error(),
            std::make_error_code(std::errc::invalid_argument));

  auto read_reply = ReadReplyPacketConfig{};
  read_reply.reply_spw_address = invalid_path;
  std::vector<uint8_t> read_reply_output(read_reply.ExpectedSize());
  auto read_reply_result = BuildReadReplyPacket(read_reply, read_reply_output);
  ASSERT_FALSE(read_reply_result.has_value());
  EXPECT_EQ(read_reply_result.error(),
            std::make_error_code(std::errc::invalid_argument));

  auto write_reply = WriteReplyPacketConfig{};
  write_reply.reply_spw_address = invalid_path;
  std::vector<uint8_t> write_reply_output(write_reply.ExpectedSize());
  auto write_reply_result =
      BuildWriteReplyPacket(write_reply, write_reply_output);
  ASSERT_FALSE(write_reply_result.has_value());
  EXPECT_EQ(write_reply_result.error(),
            std::make_error_code(std::errc::invalid_argument));
}

TEST(spw_rmap, TargetNodeAcceptsMaximumAddressLength) {
  using namespace spw_rmap;

  const std::array<uint8_t, TargetNode::kMaxAddressLen> full{};
  TargetNode node(0x34);
  node.SetTargetAddress(std::span<const uint8_t>(full));
  node.SetReplyAddress(std::span<const uint8_t>(full));

  EXPECT_EQ(node.GetTargetAddress().size(), TargetNode::kMaxAddressLen);
  EXPECT_EQ(node.GetReplyAddress().size(), TargetNode::kMaxAddressLen);
}

TEST(spw_rmap, TargetNodeDefaultLogicalAddressIsAValidLogicalAddress) {
  // `TargetNode{}` must be unambiguous and carry a logical address the packet
  // builders accept (>= 0x20).
  EXPECT_GE(spw_rmap::TargetNode{}.GetTargetLogicalAddress(), 0x20);
}

TEST(TargetNodeDeathTest, OversizedAddressTerminates) {
  using namespace spw_rmap;

  const std::array<uint8_t, TargetNode::kMaxAddressLen + 1> too_long{};
  EXPECT_DEATH(
      {
        TargetNode(0x34).SetTargetAddress(std::span<const uint8_t>(too_long));
      },
      "exceeds maximum");
  EXPECT_DEATH(
      { TargetNode(0x34).SetReplyAddress(std::span<const uint8_t>(too_long)); },
      "exceeds maximum");
  EXPECT_DEATH(
      {
        TargetNode(0x34).SetTargetAddress(
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12});
      },
      "exceeds maximum");
}

TEST(spw_rmap, ReadReplyBuilderRejectsUnencodableDataLength) {
  using namespace spw_rmap;

  std::vector<uint8_t> oversized_data(0x0100'0000U);
  auto config = ReadReplyPacketConfig{};
  config.data = oversized_data;

  auto result = BuildReadReplyPacket(config, {});

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), std::make_error_code(std::errc::invalid_argument));
}

TEST(spw_rmap, ReplyBuildersRejectInvalidReplyAddressLengthField) {
  using namespace spw_rmap;

  auto read = ReadReplyPacketConfig{};
  read.reply_address_length = 4;
  auto read_result = BuildReadReplyPacket(read, {});
  ASSERT_FALSE(read_result.has_value());
  EXPECT_EQ(read_result.error(),
            std::make_error_code(std::errc::invalid_argument));

  auto write = WriteReplyPacketConfig{};
  write.reply_address_length = 4;
  auto write_result = BuildWriteReplyPacket(write, {});
  ASSERT_FALSE(write_result.has_value());
  EXPECT_EQ(write_result.error(),
            std::make_error_code(std::errc::invalid_argument));
}

TEST(spw_rmap, ParserRejectsUnknownProtocolWithValidCrc) {
  using namespace spw_rmap;

  std::array<uint8_t, 1> reply_address{0x01};
  auto config = WriteReplyPacketConfig{
      .reply_spw_address = reply_address,
      .initiator_logical_address = 0xFE,
      .target_logical_address = 0x34,
      .transaction_id = 0x1234,
  };
  std::vector<uint8_t> packet(config.ExpectedSize());
  ASSERT_TRUE(BuildWriteReplyPacket(config, packet).has_value());
  packet[reply_address.size() + 1] = 0x02;
  packet.back() = crc::CalcCrc(std::span(packet).subspan(
      reply_address.size(), packet.size() - reply_address.size() - 1));

  auto result = ParseRMAPPacket(packet);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(),
            make_error_code(RMAPParseStatus::kUnknownProtocolIdentifier));
}

TEST(spw_rmap, ParserRejectsReservedPacketTypesAndUnsupportedCommands) {
  using namespace spw_rmap;

  auto config = ReadPacketConfig{};
  config.target_logical_address = 0x34;
  std::vector<uint8_t> valid_packet(config.ExpectedSize());
  ASSERT_TRUE(BuildReadPacket(config, valid_packet).has_value());

  const auto expect_invalid_instruction = [&valid_packet](uint8_t instruction) {
    auto packet = valid_packet;
    packet[2] = instruction;
    RecalculateHeaderCrc(packet, 0, packet.size() - 1);

    auto result = ParseRMAPPacket(packet);

    ASSERT_FALSE(result.has_value())
        << "instruction 0x" << std::hex << static_cast<int>(instruction);
    EXPECT_EQ(result.error(), make_error_code(RMAPParseStatus::kInvalidHeader));
  };

  expect_invalid_instruction(0b10001100);  // Reserved packet type 0b10.
  expect_invalid_instruction(0b11001100);  // Reserved packet type 0b11.
  expect_invalid_instruction(0b01000100);  // Invalid read command code.
  expect_invalid_instruction(0b01011100);  // Unsupported RMW command.
}

TEST(spw_rmap, ParserRejectsInvalidReadReplyHeaderFields) {
  using namespace spw_rmap;

  auto config = ReadReplyPacketConfig{};
  config.target_logical_address = 0x34;
  std::vector<uint8_t> valid_packet(config.ExpectedSize());
  ASSERT_TRUE(BuildReadReplyPacket(config, valid_packet).has_value());

  const auto expect_invalid_instruction = [&valid_packet](uint8_t instruction) {
    auto packet = valid_packet;
    packet[2] = instruction;
    RecalculateHeaderCrc(packet, 0, 11);

    auto result = ParseRMAPPacket(packet);

    ASSERT_FALSE(result.has_value())
        << "instruction 0x" << std::hex << static_cast<int>(instruction);
    EXPECT_EQ(result.error(), make_error_code(RMAPParseStatus::kInvalidHeader));
  };

  expect_invalid_instruction(0b00011100);  // RMW, not a read reply.
  expect_invalid_instruction(0b00000100);  // Reply bit is clear.

  auto nonzero_reserved_byte = valid_packet;
  nonzero_reserved_byte[7] = 0xA5;
  RecalculateHeaderCrc(nonzero_reserved_byte, 0, 11);
  auto result = ParseRMAPPacket(nonzero_reserved_byte);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), make_error_code(RMAPParseStatus::kInvalidHeader));
}

TEST(spw_rmap, EmptyReadReplyDataRoundTrips) {
  using namespace spw_rmap;

  auto config = ReadReplyPacketConfig{};
  config.initiator_logical_address = 0xFE;
  config.target_logical_address = 0x34;
  config.transaction_id = 0x1234;
  std::vector<uint8_t> packet(config.ExpectedSize());
  ASSERT_TRUE(BuildReadReplyPacket(config, packet).has_value());

  auto result = ParseRMAPPacket(packet);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->data_length, 0U);
  EXPECT_TRUE(result->data.empty());
}

TEST(spw_rmap, ReadReplyRejectsDeclaredLengthMismatch) {
  using namespace spw_rmap;

  std::array<uint8_t, 4> data{1, 2, 3, 4};
  auto config = ReadReplyPacketConfig{};
  config.initiator_logical_address = 0xFE;
  config.target_logical_address = 0x34;
  config.transaction_id = 0x1234;
  config.data = data;
  std::vector<uint8_t> packet(config.ExpectedSize());
  ASSERT_TRUE(BuildReadReplyPacket(config, packet).has_value());
  packet[10] = 5;
  packet[11] = crc::CalcCrc(std::span(packet).first(11));

  auto result = ParseRMAPPacket(packet);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(),
            make_error_code(RMAPParseStatus::kIncompletePacket));
}

TEST(spw_rmap, ErrorReadReplyRejectsTrailingData) {
  using namespace spw_rmap;

  auto config = ReadReplyPacketConfig{};
  config.initiator_logical_address = 0xFE;
  config.target_logical_address = 0x34;
  config.status = PacketStatusCode::kInvalidKey;
  std::vector<uint8_t> packet(config.ExpectedSize() + 1);
  ASSERT_TRUE(BuildReadReplyPacket(config, packet).has_value());

  auto result = ParseRMAPPacket(packet);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(),
            make_error_code(RMAPParseStatus::kIncompletePacket));
}

TEST(spw_rmap, ReplyAddressPaddingRoundTripsEveryLength) {
  using namespace spw_rmap;

  for (std::size_t length = 1; length <= TargetNode::kMaxAddressLen; ++length) {
    std::vector<uint8_t> reply_address(length);
    for (std::size_t i = 0; i < length; ++i) {
      reply_address[i] = static_cast<uint8_t>(i + 1);
    }
    auto config = ReadPacketConfig{};
    config.target_logical_address = 0x34;
    config.reply_address = reply_address;
    std::vector<uint8_t> packet(config.ExpectedSize());
    ASSERT_TRUE(BuildReadPacket(config, packet).has_value());

    auto result = ParseRMAPPacket(packet);

    ASSERT_TRUE(result.has_value()) << "reply length " << length;
    EXPECT_TRUE(SpanEqual(result->reply_address, config.reply_address));
  }
}

TEST(spw_rmap, AllZeroReplyAddressMapsToSingleZeroRoute) {
  using namespace spw_rmap;

  const std::array<uint8_t, 1> zero_route{0x00};
  auto read = ReadPacketConfig{};
  read.target_logical_address = 0x34;
  read.reply_address = zero_route;
  std::vector<uint8_t> read_packet(read.ExpectedSize());
  ASSERT_TRUE(BuildReadPacket(read, read_packet).has_value());

  auto parsed_read = ParseRMAPPacket(read_packet);
  ASSERT_TRUE(parsed_read.has_value());
  ASSERT_EQ(parsed_read->reply_address.size(), 1U);
  EXPECT_EQ(parsed_read->reply_address.front(), 0x00);

  const std::array<uint8_t, 1> data{0x5A};
  auto write = WritePacketConfig{};
  write.target_logical_address = 0x34;
  write.reply_address = zero_route;
  write.data = data;
  std::vector<uint8_t> write_packet(write.ExpectedSize());
  ASSERT_TRUE(BuildWritePacket(write, write_packet).has_value());

  auto parsed_write = ParseRMAPPacket(write_packet);
  ASSERT_TRUE(parsed_write.has_value());
  ASSERT_EQ(parsed_write->reply_address.size(), 1U);
  EXPECT_EQ(parsed_write->reply_address.front(), 0x00);
}
