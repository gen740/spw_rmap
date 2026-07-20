#include <gmock/gmock.h>
#include <gtest/gtest-matchers.h>
#include <gtest/gtest.h>

#include <random>
#include <spw_rmap/error_code.hh>
#include <spw_rmap/packet_builder.hh>
#include <spw_rmap/packet_parser.hh>
#include <system_error>

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
        .increment_mode = RandomByte() % 2 == 0,
        .data = data,
    };

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
