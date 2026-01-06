#include <gmock/gmock.h>
#include <gtest/gtest-matchers.h>
#include <gtest/gtest.h>

#include <random>
#include <spw_rmap/packet_builder.hh>
#include <spw_rmap/packet_parser.hh>

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
    std::ignore = node.setTargetAddress(target_address);
    std::ignore = node.setReplyAddress(reply_address);

    auto c = ReadPacketConfig{
        .target_spw_address = node.getTargetAddress(),
        .target_logical_address = node.getTargetLogicalAddress(),
        .reply_address = node.getReplyAddress(),
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
    EXPECT_TRUE(SpanEqual(d.targetSpaceWireAddress, c.target_spw_address));
    EXPECT_TRUE(SpanEqual(d.replyAddress, c.reply_address));
    EXPECT_EQ(d.targetLogicalAddress, c.target_logical_address);
    EXPECT_EQ(d.initiatorLogicalAddress, c.initiator_logical_address);
    EXPECT_EQ(d.transactionID, c.transaction_id);
    EXPECT_EQ(d.extendedAddress, c.extended_address);
    EXPECT_EQ(d.address, c.address);
    EXPECT_EQ(d.dataLength, c.data_length);
    EXPECT_EQ(d.key, c.key);
    EXPECT_EQ(d.type, PacketType::Read);
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
    std::ignore = node.setTargetAddress(target_address);
    std::ignore = node.setReplyAddress(reply_address);

    std::vector<uint8_t> data;

    for (size_t i = 0; i < RandomDataLength(); ++i) {
      data.push_back(RandomByte());
    }

    auto c = ReadReplyPacketConfig{
        .reply_spw_address = node.getReplyAddress(),
        .target_logical_address = node.getTargetLogicalAddress(),
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
    EXPECT_TRUE(SpanEqual(d.replyAddress, c.reply_spw_address));
    EXPECT_EQ(d.status, c.status);
    EXPECT_EQ(d.targetLogicalAddress, c.target_logical_address);
    EXPECT_EQ(d.transactionID, c.transaction_id);
    EXPECT_TRUE(SpanEqual(d.data, c.data));
    EXPECT_EQ(d.type, PacketType::ReadReply);
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
    std::ignore = node.setTargetAddress(target_address);
    std::ignore = node.setReplyAddress(reply_address);

    std::vector<uint8_t> data;

    for (size_t i = 0; i < RandomDataLength(); ++i) {
      data.push_back(RandomByte());
    }

    auto c = WritePacketConfig{
        .target_spw_address = node.getTargetAddress(),
        .target_logical_address = node.getTargetLogicalAddress(),
        .reply_address = node.getReplyAddress(),
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
    EXPECT_TRUE(SpanEqual(d.targetSpaceWireAddress, c.target_spw_address));
    EXPECT_TRUE(SpanEqual(d.replyAddress, c.reply_address));
    EXPECT_EQ(d.targetLogicalAddress, c.target_logical_address);
    EXPECT_EQ(d.initiatorLogicalAddress, c.initiator_logical_address);
    EXPECT_EQ(d.transactionID, c.transaction_id);
    EXPECT_EQ(d.key, c.key);
    EXPECT_EQ(d.extendedAddress, c.extended_address);
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
    std::ignore = node.setTargetAddress(target_address);
    std::ignore = node.setReplyAddress(reply_address);

    auto c = WriteReplyPacketConfig{
        .reply_spw_address = node.getReplyAddress(),
        .initiator_logical_address = RandomLogicalAddress(),
        .target_logical_address = node.getTargetLogicalAddress(),
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
    EXPECT_TRUE(SpanEqual(d.replyAddress, c.reply_spw_address));
    EXPECT_EQ(d.initiatorLogicalAddress, c.initiator_logical_address);
    EXPECT_EQ(d.status, c.status);
    EXPECT_EQ(d.targetLogicalAddress, c.target_logical_address);
    EXPECT_EQ(d.transactionID, c.transaction_id);
    EXPECT_EQ(d.type, PacketType::WriteReply);
    EXPECT_EQ(d.instruction & 0b00000100, c.increment_mode ? 0b00000100 : 0);
  }
}
