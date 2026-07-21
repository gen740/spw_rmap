#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <expected>
#include <future>
#include <mutex>
#include <span>
#include <stdexcept>
#include <thread>
#include <vector>

#include "spw_rmap/internal/spw_rmap_tcp_node_impl.hh"
#include "spw_rmap/packet_builder.hh"
#include "spw_rmap/spw_rmap_tcp_node.hh"
#include "spw_rmap/target_node.hh"

namespace {

class MockBackend {
 public:
  MockBackend(std::string ip, std::string port)
      : ip_address_(std::move(ip)), port_(std::move(port)) {}

  [[nodiscard]] auto GetIpAddress() const noexcept -> const std::string& {
    return ip_address_;
  }

  auto SetIpAddress(std::string ip_address) noexcept -> void {
    ip_address_ = std::move(ip_address);
  }

  [[nodiscard]] auto GetPort() const noexcept -> const std::string& {
    return port_;
  }

  auto SetPort(std::string port) noexcept -> void { port_ = std::move(port); }

  auto SetSendTimeout(std::chrono::microseconds /*timeout*/) noexcept
      -> std::expected<void, std::error_code> {
    return {};
  }

  auto SetReceiveTimeout(std::chrono::microseconds /*timeout*/) noexcept
      -> std::expected<void, std::error_code> {
    return {};
  }

  auto SendAll(std::span<const uint8_t> data) noexcept
      -> std::expected<void, std::error_code> {
    {
      std::lock_guard<std::mutex> lock(mtx_);
      sent_frames_.emplace_back(data.begin(), data.end());
    }
    cv_.notify_all();
    return {};
  }

  auto RecvSome(std::span<uint8_t> buffer) noexcept
      -> std::expected<std::size_t, std::error_code> {
    if (buffer.empty()) {
      return 0U;
    }
    std::unique_lock<std::mutex> lock(mtx_);
    cv_.wait(lock,
             [&] -> bool { return shutdown_ || !incoming_bytes_.empty(); });
    if (incoming_bytes_.empty()) {
      return std::unexpected{
          std::make_error_code(std::errc::operation_canceled)};
    }
    const auto count = std::min(
        buffer.size(), static_cast<std::size_t>(incoming_bytes_.size()));
    for (std::size_t i = 0; i < count; ++i) {
      buffer[i] = incoming_bytes_.front();
      incoming_bytes_.pop_front();
    }
    return count;
  }

  auto Shutdown() noexcept -> std::expected<void, std::error_code> {
    {
      std::lock_guard<std::mutex> lock(mtx_);
      shutdown_ = true;
    }
    cv_.notify_all();
    return {};
  }

  [[nodiscard]] auto IsShutdown() const noexcept -> bool { return shutdown_; }

  auto Connect(std::chrono::microseconds /*timeout*/) noexcept
      -> std::expected<void, std::error_code> {
    return {};
  }

  auto EnsureConnect() noexcept -> std::expected<void, std::error_code> {
    if (shutdown_) {
      shutdown_ = false;
    }
    return {};
  }

  void EnqueueIncoming(const std::vector<uint8_t>& data) {
    {
      std::lock_guard<std::mutex> lock(mtx_);
      for (auto byte : data) {
        incoming_bytes_.push_back(byte);
      }
    }
    cv_.notify_all();
  }

  [[nodiscard]] auto SentFrames() const
      -> const std::vector<std::vector<uint8_t>>& {
    return sent_frames_;
  }

  auto WaitForSentFrames(std::size_t count, std::chrono::milliseconds timeout)
      -> bool {
    std::unique_lock<std::mutex> lock(mtx_);
    return cv_.wait_for(lock, timeout,
                        [this, count] { return sent_frames_.size() >= count; });
  }

 private:
  std::string ip_address_;
  std::string port_;
  std::vector<std::vector<uint8_t>> sent_frames_;
  std::deque<uint8_t> incoming_bytes_;
  std::mutex mtx_;
  std::condition_variable cv_;
  bool shutdown_ = false;
};

class TestNode : public spw_rmap::internal::SpwRmapTCPNodeImpl<MockBackend> {
  using Base = spw_rmap::internal::SpwRmapTCPNodeImpl<MockBackend>;

 public:
  TestNode(const TestNode&) = delete;
  TestNode(TestNode&&) = delete;
  auto operator=(const TestNode&) -> TestNode& = delete;
  auto operator=(TestNode&&) -> TestNode& = delete;
  explicit TestNode(spw_rmap::SpwRmapTCPNodeConfig config)
      : Base(std::move(config)) {}
  ~TestNode() override = default;

  void EnqueueIncoming(const std::vector<uint8_t>& frame) {
    Backend().EnqueueIncoming(frame);
  }

  [[nodiscard]] auto SentFrames() -> const std::vector<std::vector<uint8_t>>& {
    return Backend().SentFrames();
  }

  auto WaitForSentFrames(std::size_t count, std::chrono::milliseconds timeout)
      -> bool {
    return Backend().WaitForSentFrames(count, timeout);
  }

  auto Stop() noexcept -> std::expected<void, std::error_code> override {
    RequestRunLoopStop();
    return Backend().Shutdown();
  }

  auto Shutdown() noexcept -> std::expected<void, std::error_code> override {
    auto result = Backend().Shutdown();
    if (result.has_value()) {
      GetBackend().reset();
    }
    return result;
  }

  auto IsShutdowned() noexcept -> bool override {
    return Backend().IsShutdown();
  }

 private:
  using Base::GetBackend;

  auto Backend() -> MockBackend& { return *GetBackend(); }
};

class NullBackendTCPClient : public spw_rmap::SpwRmapTCPClient {
 public:
  using SpwRmapTCPClient::SpwRmapTCPClient;

  auto ResetBackend() noexcept -> void { GetBackend().reset(); }
};

auto MakeFrame(std::span<const uint8_t> payload, uint8_t type = 0x00)
    -> std::vector<uint8_t> {
  std::vector<uint8_t> frame(12 + payload.size());
  frame[0] = type;
  frame[1] = 0x00;
  frame[2] = 0x00;
  frame[3] = 0x00;
  const uint64_t length = payload.size();
  frame[4] = static_cast<uint8_t>((length >> 56) & 0xFF);
  frame[5] = static_cast<uint8_t>((length >> 48) & 0xFF);
  frame[6] = static_cast<uint8_t>((length >> 40) & 0xFF);
  frame[7] = static_cast<uint8_t>((length >> 32) & 0xFF);
  frame[8] = static_cast<uint8_t>((length >> 24) & 0xFF);
  frame[9] = static_cast<uint8_t>((length >> 16) & 0xFF);
  frame[10] = static_cast<uint8_t>((length >> 8) & 0xFF);
  frame[11] = static_cast<uint8_t>(length & 0xFF);
  std::ranges::copy(payload, frame.begin() + 12);
  return frame;
}

auto BuildWriteReplyFrame(
    uint16_t transaction_id,
    spw_rmap::PacketStatusCode status =
        spw_rmap::PacketStatusCode::kCommandExecutedSuccessfully)
    -> std::vector<uint8_t> {
  auto reply_addr = std::array<uint8_t, 1>{0x01};
  auto config = spw_rmap::WriteReplyPacketConfig{
      .reply_spw_address = reply_addr,
      .initiator_logical_address = 0x34,
      .target_logical_address = 0xFE,
      .transaction_id = transaction_id,
      .status = status,
      .reply_address_length = 1,
      .increment_mode = true,
      .verify_mode = true,
  };
  std::vector<uint8_t> payload(config.ExpectedSize());
  EXPECT_TRUE(spw_rmap::BuildWriteReplyPacket(config, payload).has_value());
  return MakeFrame(payload);
}

auto BuildReadReplyFrame(
    uint16_t transaction_id, std::span<const uint8_t> data,
    spw_rmap::PacketStatusCode status =
        spw_rmap::PacketStatusCode::kCommandExecutedSuccessfully)
    -> std::vector<uint8_t> {
  auto reply_addr = std::array<uint8_t, 1>{0x01};
  auto config = spw_rmap::ReadReplyPacketConfig{
      .reply_spw_address = reply_addr,
      .initiator_logical_address = 0x34,
      .target_logical_address = 0xFE,
      .transaction_id = transaction_id,
      .status = status,
      .reply_address_length = 1,
      .increment_mode = true,
      .data = data,
  };
  std::vector<uint8_t> payload(config.ExpectedSize());
  EXPECT_TRUE(spw_rmap::BuildReadReplyPacket(config, payload).has_value());
  return MakeFrame(payload);
}

auto BuildReadCommandFrame(uint16_t transaction_id, uint32_t data_length,
                           std::span<const uint8_t> reply_address = {},
                           uint8_t initiator_logical_address = 0xFE,
                           bool increment_mode = true) -> std::vector<uint8_t> {
  auto config = spw_rmap::ReadPacketConfig{};
  config.target_logical_address = 0x34;
  config.reply_address = reply_address;
  config.initiator_logical_address = initiator_logical_address;
  config.transaction_id = transaction_id;
  config.address = 0x1000;
  config.data_length = data_length;
  config.increment_mode = increment_mode;
  std::vector<uint8_t> payload(config.ExpectedSize());
  EXPECT_TRUE(spw_rmap::BuildReadPacket(config, payload).has_value());
  return MakeFrame(payload);
}

auto BuildWriteCommandFrame(uint16_t transaction_id,
                            std::span<const uint8_t> data,
                            std::span<const uint8_t> reply_address = {},
                            uint8_t initiator_logical_address = 0xFE,
                            bool reply = true, bool increment_mode = true,
                            bool verify_mode = true) -> std::vector<uint8_t> {
  auto config = spw_rmap::WritePacketConfig{};
  config.target_logical_address = 0x34;
  config.reply_address = reply_address;
  config.initiator_logical_address = initiator_logical_address;
  config.transaction_id = transaction_id;
  config.address = 0x1000;
  config.reply = reply;
  config.increment_mode = increment_mode;
  config.verify_mode = verify_mode;
  config.data = data;
  std::vector<uint8_t> payload(config.ExpectedSize());
  EXPECT_TRUE(spw_rmap::BuildWritePacket(config, payload).has_value());
  return MakeFrame(payload);
}

auto MakeTimecodeFrame(uint8_t timecode) -> std::vector<uint8_t> {
  std::vector<uint8_t> frame(14, 0);
  frame[0] = 0x30;
  frame[11] = 0x02;
  frame[12] = timecode;
  return frame;
}

auto MakeNodeConfig() -> spw_rmap::SpwRmapTCPNodeConfig {
  spw_rmap::SpwRmapTCPNodeConfig config;
  config.ip_address = "127.0.0.1";
  config.port = "10030";
  config.send_buffer_size = 512;
  config.recv_buffer_size = 512;
  return config;
}

TEST(SpwRmapTCPNodeImplTest, WriteAsyncCompletesAfterPoll) {
  TestNode node(MakeNodeConfig());
  auto target_node = spw_rmap::TargetNode(0x34)
                         .SetTargetAddress(0x02, 0x03)
                         .SetReplyAddress(0x10, 0x11);

  std::array<uint8_t, 4> payload{0xAA, 0xBB, 0xCC, 0xDD};
  std::atomic<bool> callback_called{false};

  auto write_res = node.WriteAsync(
      target_node, 0x1000, payload,
      [&callback_called](
          std::expected<spw_rmap::Packet, std::error_code> packet) -> void {
        callback_called = true;
        EXPECT_TRUE(packet.has_value());
        EXPECT_EQ(packet.value().type, spw_rmap::PacketType::kWriteReply);
      });

  ASSERT_TRUE(write_res.has_value());
  auto transaction_id = write_res.value();

  node.EnqueueIncoming(BuildWriteReplyFrame(transaction_id));

  auto poll_result = node.Poll();
  ASSERT_TRUE(poll_result.has_value());

  EXPECT_TRUE(callback_called.load());
}

TEST(SpwRmapTCPNodeImplTest, AsyncOperationsRejectEmptyCompletionCallback) {
  TestNode node(MakeNodeConfig());
  auto target_node = spw_rmap::TargetNode(0x34);
  const std::array<uint8_t, 1> payload{0x12};

  auto write_result = node.WriteAsync(target_node, 0x1000, payload, {});
  auto read_result = node.ReadAsync(target_node, 0x1000, 1, {});

  ASSERT_FALSE(write_result.has_value());
  EXPECT_EQ(write_result.error(),
            std::make_error_code(std::errc::invalid_argument));
  ASSERT_FALSE(read_result.has_value());
  EXPECT_EQ(read_result.error(),
            std::make_error_code(std::errc::invalid_argument));
}

TEST(SpwRmapTCPNodeImplTest, ReadRejectsUnencodableDataLength) {
  TestNode node(MakeNodeConfig());
  auto target_node = spw_rmap::TargetNode(0x34);
  std::vector<uint8_t> data(0x0100'0000U);

  auto result = node.Read(target_node, 0x1000, data);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), std::make_error_code(std::errc::invalid_argument));
}

TEST(SpwRmapTCPNodeImplTest, EnsureConnectionAfterShutdownBackendIsSafe) {
  TestNode node(MakeNodeConfig());
  ASSERT_TRUE(node.Shutdown().has_value());

  auto result = node.EnsureTcpConnection();

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), std::make_error_code(std::errc::not_connected));
}

TEST(SpwRmapTCPNodeImplTest, PublicOperationsAfterShutdownReturnNotConnected) {
  TestNode node(MakeNodeConfig());
  ASSERT_TRUE(node.Shutdown().has_value());

  auto target_node = spw_rmap::TargetNode(0x34);
  std::array<uint8_t, 1> data{0x12};
  auto expect_not_connected = [](const auto& result) -> void {
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), std::make_error_code(std::errc::not_connected));
  };

  expect_not_connected(node.Poll());
  expect_not_connected(node.RunLoop());
  expect_not_connected(node.Write(target_node, 0x1000, data));
  expect_not_connected(node.WriteAsync(target_node, 0x1000, data, [](auto) {}));
  expect_not_connected(node.Read(target_node, 0x1000, data));
  expect_not_connected(
      node.ReadAsync(target_node, 0x1000, data.size(), [](auto) {}));
  expect_not_connected(node.EmitTimeCode(0x12));
}

TEST(SpwRmapTCPClientTest, LifecycleOperationsWithNullBackendAreSafe) {
  NullBackendTCPClient client(MakeNodeConfig());
  client.ResetBackend();

  auto connect_result = client.Connect();
  ASSERT_FALSE(connect_result.has_value());
  EXPECT_EQ(connect_result.error(),
            std::make_error_code(std::errc::not_connected));

  auto timeout_result = client.SetSendTimeout(std::chrono::milliseconds(100));
  ASSERT_FALSE(timeout_result.has_value());
  EXPECT_EQ(timeout_result.error(),
            std::make_error_code(std::errc::not_connected));

  EXPECT_TRUE(client.Stop().has_value());
  EXPECT_TRUE(client.Shutdown().has_value());
  EXPECT_TRUE(client.IsShutdowned());
}

TEST(SpwRmapTCPNodeImplTest, StopInterruptsBlockingRunLoop) {
  TestNode node(MakeNodeConfig());
  auto loop =
      std::async(std::launch::async, [&node]() { return node.RunLoop(); });
  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  auto stop_result = node.Stop();

  ASSERT_TRUE(stop_result.has_value()) << stop_result.error().message();
  ASSERT_EQ(loop.wait_for(std::chrono::seconds(1)), std::future_status::ready);
  auto loop_result = loop.get();
  EXPECT_TRUE(loop_result.has_value()) << loop_result.error().message();
}

TEST(SpwRmapTCPNodeImplTest, AutoPollingWriteCompletesSynchronously) {
  TestNode node(MakeNodeConfig());
  node.SetAutoPollingMode(true);
  node.EnqueueIncoming(BuildWriteReplyFrame(0));
  auto target_node = spw_rmap::TargetNode(0x34);
  std::array<uint8_t, 2> payload{0x12, 0x34};

  auto result =
      node.Write(target_node, 0x1000, payload, std::chrono::milliseconds(100));

  EXPECT_TRUE(result.has_value()) << result.error().message();
}

TEST(SpwRmapTCPNodeImplTest, AutoPollingWriteReturnsRmapStatusError) {
  TestNode node(MakeNodeConfig());
  node.SetAutoPollingMode(true);
  node.EnqueueIncoming(
      BuildWriteReplyFrame(0, spw_rmap::PacketStatusCode::kInvalidKey));
  auto target_node = spw_rmap::TargetNode(0x34);
  const std::array<uint8_t, 1> payload{0x12};

  auto result =
      node.Write(target_node, 0x1000, payload, std::chrono::milliseconds(100));

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(),
            spw_rmap::make_error_code(spw_rmap::PacketStatusCode::kInvalidKey));
}

TEST(SpwRmapTCPNodeImplTest, BackgroundPollingWriteReturnsRmapStatusError) {
  TestNode node(MakeNodeConfig());
  auto target_node = spw_rmap::TargetNode(0x34);
  const std::array<uint8_t, 1> payload{0x12};
  auto operation = std::async(std::launch::async, [&] {
    return node.Write(target_node, 0x1000, payload,
                      std::chrono::milliseconds(500));
  });
  ASSERT_TRUE(node.WaitForSentFrames(1, std::chrono::milliseconds(100)));
  node.EnqueueIncoming(
      BuildWriteReplyFrame(0, spw_rmap::PacketStatusCode::kInvalidKey));

  ASSERT_TRUE(node.Poll().has_value());
  auto result = operation.get();

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(),
            spw_rmap::make_error_code(spw_rmap::PacketStatusCode::kInvalidKey));
}

TEST(SpwRmapTCPNodeImplTest, BackgroundPollingWriteRejectsReadReply) {
  TestNode node(MakeNodeConfig());
  auto target_node = spw_rmap::TargetNode(0x34);
  const std::array<uint8_t, 1> payload{0x12};
  auto operation = std::async(std::launch::async, [&] {
    return node.Write(target_node, 0x1000, payload,
                      std::chrono::milliseconds(500));
  });
  ASSERT_TRUE(node.WaitForSentFrames(1, std::chrono::milliseconds(100)));
  node.EnqueueIncoming(BuildReadReplyFrame(0, {}));

  ASSERT_TRUE(node.Poll().has_value());
  auto result = operation.get();

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), std::make_error_code(std::errc::bad_message));
}

TEST(SpwRmapTCPNodeImplTest, AutoPollingReadCopiesReplyData) {
  TestNode node(MakeNodeConfig());
  node.SetAutoPollingMode(true);
  std::array<uint8_t, 4> expected{0x12, 0x34, 0x56, 0x78};
  node.EnqueueIncoming(BuildReadReplyFrame(0, expected));
  auto target_node = spw_rmap::TargetNode(0x34);
  std::array<uint8_t, 4> received{};

  auto result =
      node.Read(target_node, 0x1000, received, std::chrono::milliseconds(100));

  EXPECT_TRUE(result.has_value()) << result.error().message();
  EXPECT_EQ(received, expected);
}

TEST(SpwRmapTCPNodeImplTest, AutoPollingReadReturnsRmapStatusError) {
  TestNode node(MakeNodeConfig());
  node.SetAutoPollingMode(true);
  const std::array<uint8_t, 4> reply_data{0x12, 0x34, 0x56, 0x78};
  node.EnqueueIncoming(BuildReadReplyFrame(
      0, reply_data, spw_rmap::PacketStatusCode::kInvalidKey));
  auto target_node = spw_rmap::TargetNode(0x34);
  std::array<uint8_t, 4> received{};

  auto result =
      node.Read(target_node, 0x1000, received, std::chrono::milliseconds(100));

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(),
            spw_rmap::make_error_code(spw_rmap::PacketStatusCode::kInvalidKey));
}

TEST(SpwRmapTCPNodeImplTest, BackgroundPollingReadReturnsRmapStatusError) {
  TestNode node(MakeNodeConfig());
  auto target_node = spw_rmap::TargetNode(0x34);
  std::array<uint8_t, 4> received{};
  const std::array<uint8_t, 4> reply_data{0x12, 0x34, 0x56, 0x78};
  auto operation = std::async(std::launch::async, [&] {
    return node.Read(target_node, 0x1000, received,
                     std::chrono::milliseconds(500));
  });
  ASSERT_TRUE(node.WaitForSentFrames(1, std::chrono::milliseconds(100)));
  node.EnqueueIncoming(BuildReadReplyFrame(
      0, reply_data, spw_rmap::PacketStatusCode::kInvalidKey));

  ASSERT_TRUE(node.Poll().has_value());
  auto result = operation.get();

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(),
            spw_rmap::make_error_code(spw_rmap::PacketStatusCode::kInvalidKey));
}

TEST(SpwRmapTCPNodeImplTest, BackgroundPollingReadRejectsWriteReply) {
  TestNode node(MakeNodeConfig());
  auto target_node = spw_rmap::TargetNode(0x34);
  std::array<uint8_t, 4> received{};
  auto operation = std::async(std::launch::async, [&] {
    return node.Read(target_node, 0x1000, received,
                     std::chrono::milliseconds(500));
  });
  ASSERT_TRUE(node.WaitForSentFrames(1, std::chrono::milliseconds(100)));
  node.EnqueueIncoming(BuildWriteReplyFrame(0));

  ASSERT_TRUE(node.Poll().has_value());
  auto result = operation.get();

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), std::make_error_code(std::errc::bad_message));
}

TEST(SpwRmapTCPNodeImplTest, AutoPollingRejectsUnexpectedTransactionId) {
  TestNode node(MakeNodeConfig());
  node.SetAutoPollingMode(true);
  node.EnqueueIncoming(BuildWriteReplyFrame(1));
  auto target_node = spw_rmap::TargetNode(0x34);
  std::array<uint8_t, 1> payload{0x12};

  auto result =
      node.Write(target_node, 0x1000, payload, std::chrono::milliseconds(100));

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), std::make_error_code(std::errc::bad_message));
}

TEST(SpwRmapTCPNodeImplTest, TimecodeWithoutCallbackDoesNotAbortPolling) {
  TestNode node(MakeNodeConfig());
  std::atomic<bool> callback_called{false};
  auto target_node = spw_rmap::TargetNode(0x34);
  std::array<uint8_t, 1> payload{0x12};
  auto transaction = node.WriteAsync(target_node, 0x1000, payload,
                                     [&callback_called](auto result) -> void {
                                       callback_called = result.has_value();
                                     });
  ASSERT_TRUE(transaction.has_value());
  node.EnqueueIncoming(MakeTimecodeFrame(0x15));
  node.EnqueueIncoming(BuildWriteReplyFrame(*transaction));

  auto result = node.Poll();

  EXPECT_TRUE(result.has_value()) << result.error().message();
  EXPECT_FALSE(callback_called.load());
  EXPECT_TRUE(node.Poll().has_value());
  EXPECT_TRUE(callback_called.load());
}

TEST(SpwRmapTCPNodeImplTest, RegisteredTimecodeCallbackReceivesSixBits) {
  TestNode node(MakeNodeConfig());
  std::optional<uint8_t> received_timecode;
  node.RegisterOnTimeCode([&received_timecode](uint8_t timecode) -> void {
    received_timecode = timecode;
  });
  std::atomic<bool> reply_received{false};
  auto target_node = spw_rmap::TargetNode(0x34);
  std::array<uint8_t, 1> payload{0x12};
  auto transaction = node.WriteAsync(target_node, 0x1000, payload,
                                     [&reply_received](auto result) -> void {
                                       reply_received = result.has_value();
                                     });
  ASSERT_TRUE(transaction.has_value());
  node.EnqueueIncoming(MakeTimecodeFrame(0xD5));
  node.EnqueueIncoming(BuildWriteReplyFrame(*transaction));

  ASSERT_TRUE(node.Poll().has_value());

  ASSERT_TRUE(received_timecode.has_value());
  EXPECT_EQ(*received_timecode, 0x15);
  EXPECT_FALSE(reply_received.load());
  ASSERT_TRUE(node.Poll().has_value());
  EXPECT_TRUE(reply_received.load());
}

TEST(SpwRmapTCPNodeImplTest, FixedReceiveBufferRejectsOversizedFrame) {
  auto config = MakeNodeConfig();
  config.recv_buffer_size = 8;
  config.buffer_policy = spw_rmap::BufferPolicy::kFixed;
  TestNode node(config);
  std::array<uint8_t, 12> header{};
  header[0] = 0x00;
  header[11] = 0x09;
  node.EnqueueIncoming(std::vector<uint8_t>(header.begin(), header.end()));

  auto result = node.Poll();

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), std::make_error_code(std::errc::no_buffer_space));
}

TEST(SpwRmapTCPNodeImplTest, AutoResizeRejectsFrameAboveConfiguredMaximum) {
  auto config = MakeNodeConfig();
  config.recv_buffer_size = 8;
  config.max_receive_frame_size = 8;
  config.buffer_policy = spw_rmap::BufferPolicy::kAutoResize;
  TestNode node(config);
  std::array<uint8_t, 12> header{};
  header[0] = 0x00;
  header[11] = 0x09;
  node.EnqueueIncoming(std::vector<uint8_t>(header.begin(), header.end()));

  auto result = node.Poll();

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), std::make_error_code(std::errc::message_size));
}

TEST(SpwRmapTCPNodeImplTest, ContinuedFramesAreReassembled) {
  TestNode node(MakeNodeConfig());
  std::atomic<bool> callback_called{false};
  auto target_node = spw_rmap::TargetNode(0x34);
  std::array<uint8_t, 1> data{0x12};
  auto transaction = node.WriteAsync(target_node, 0x1000, data,
                                     [&callback_called](auto result) -> void {
                                       callback_called = result.has_value();
                                     });
  ASSERT_TRUE(transaction.has_value());
  auto complete_frame = BuildWriteReplyFrame(*transaction);
  auto payload = std::span(complete_frame).subspan(12);
  const auto split = payload.size() / 2;
  node.EnqueueIncoming(MakeFrame(payload.first(split), 0x02));
  node.EnqueueIncoming(MakeFrame(payload.subspan(split), 0x00));

  auto result = node.Poll();

  EXPECT_TRUE(result.has_value()) << result.error().message();
  EXPECT_TRUE(callback_called.load());
}

TEST(SpwRmapTCPNodeImplTest, IgnoredFrameDoesNotConsumeFollowingPacket) {
  TestNode node(MakeNodeConfig());
  std::atomic<bool> callback_called{false};
  auto target_node = spw_rmap::TargetNode(0x34);
  std::array<uint8_t, 1> data{0x12};
  auto transaction = node.WriteAsync(target_node, 0x1000, data,
                                     [&callback_called](auto result) -> void {
                                       callback_called = result.has_value();
                                     });
  ASSERT_TRUE(transaction.has_value());
  std::array<uint8_t, 3> ignored{0xAA, 0xBB, 0xCC};
  node.EnqueueIncoming(MakeFrame(ignored, 0x01));
  node.EnqueueIncoming(BuildWriteReplyFrame(*transaction));

  auto result = node.Poll();

  EXPECT_TRUE(result.has_value()) << result.error().message();
  EXPECT_TRUE(callback_called.load());
}

TEST(SpwRmapTCPNodeImplTest, IgnoredFrameDiscardsEarlierContinuation) {
  TestNode node(MakeNodeConfig());
  std::atomic<bool> callback_called{false};
  auto target_node = spw_rmap::TargetNode(0x34);
  std::array<uint8_t, 1> data{0x12};
  auto transaction = node.WriteAsync(target_node, 0x1000, data,
                                     [&callback_called](auto result) -> void {
                                       callback_called = result.has_value();
                                     });
  ASSERT_TRUE(transaction.has_value());

  std::array<uint8_t, 2> abandoned_continuation{0xAA, 0xBB};
  std::array<uint8_t, 1> ignored{0xCC};
  node.EnqueueIncoming(MakeFrame(abandoned_continuation, 0x02));
  node.EnqueueIncoming(MakeFrame(ignored, 0x01));
  node.EnqueueIncoming(BuildWriteReplyFrame(*transaction));

  auto result = node.Poll();

  EXPECT_TRUE(result.has_value()) << result.error().message();
  EXPECT_TRUE(callback_called.load());
}

TEST(SpwRmapTCPNodeImplTest, ManyIgnoredFramesDoNotGrowTheCallStack) {
  TestNode node(MakeNodeConfig());
  std::atomic<bool> callback_called{false};
  auto target_node = spw_rmap::TargetNode(0x34);
  std::array<uint8_t, 1> data{0x12};
  auto transaction = node.WriteAsync(target_node, 0x1000, data,
                                     [&callback_called](auto result) -> void {
                                       callback_called = result.has_value();
                                     });
  ASSERT_TRUE(transaction.has_value());

  constexpr std::size_t kIgnoredFrameCount = 10'000;
  const auto ignored_frame = MakeFrame(std::array<uint8_t, 1>{0xAA}, 0x01);
  const auto reply_frame = BuildWriteReplyFrame(*transaction);
  std::vector<uint8_t> incoming;
  incoming.reserve(kIgnoredFrameCount * ignored_frame.size() +
                   reply_frame.size());
  for (std::size_t i = 0; i < kIgnoredFrameCount; ++i) {
    incoming.insert(incoming.end(), ignored_frame.begin(), ignored_frame.end());
  }
  incoming.insert(incoming.end(), reply_frame.begin(), reply_frame.end());
  node.EnqueueIncoming(incoming);

  auto result = node.Poll();

  EXPECT_TRUE(result.has_value()) << result.error().message();
  EXPECT_TRUE(callback_called.load());
}

TEST(SpwRmapTCPNodeImplTest, InvalidTimecodePayloadIsRejected) {
  TestNode node(MakeNodeConfig());
  auto frame = MakeTimecodeFrame(0x15);
  frame[13] = 0x01;
  node.EnqueueIncoming(frame);

  auto result = node.Poll();

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), std::make_error_code(std::errc::bad_message));
}

TEST(SpwRmapTCPNodeImplTest, ReservedHeaderByteIsRejected) {
  TestNode node(MakeNodeConfig());
  auto frame = BuildWriteReplyFrame(0);
  frame[1] = 0x01;
  node.EnqueueIncoming(frame);

  auto result = node.Poll();

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), std::make_error_code(std::errc::bad_message));
}

#ifdef __EXCEPTIONS
TEST(SpwRmapTCPNodeImplTest, ReadCallbackExceptionTerminates) {
  EXPECT_DEATH(
      {
        TestNode node(MakeNodeConfig());
        node.RegisterOnRead([](spw_rmap::Packet) -> std::vector<uint8_t> {
          throw std::runtime_error("callback failure");
        });
        node.EnqueueIncoming(BuildReadCommandFrame(0, 4));
        static_cast<void>(node.Poll());
      },
      "");
}
#endif

TEST(SpwRmapTCPNodeImplTest,
     TargetReadReplyCopiesCommandFieldsAndPreservesSingleZeroRoute) {
  TestNode node(MakeNodeConfig());
  node.RegisterOnRead([](spw_rmap::Packet packet) -> std::vector<uint8_t> {
    return std::vector<uint8_t>(packet.data_length, 0x5A);
  });
  const std::array<uint8_t, 1> zero_route{0x00};
  auto command_frame =
      BuildReadCommandFrame(0x1234, 2, zero_route, 0xA5, false);
  auto command =
      spw_rmap::ParseRMAPPacket(std::span(command_frame).subspan(12));
  ASSERT_TRUE(command.has_value());
  node.EnqueueIncoming(command_frame);

  ASSERT_TRUE(node.Poll().has_value());

  ASSERT_EQ(node.SentFrames().size(), 1U);
  auto reply = spw_rmap::ParseRMAPPacket(
      std::span(node.SentFrames().front()).subspan(12));
  ASSERT_TRUE(reply.has_value());
  EXPECT_EQ(reply->type, spw_rmap::PacketType::kReadReply);
  EXPECT_EQ(reply->initiator_logical_address, 0xA5);
  EXPECT_EQ(reply->target_logical_address, 0x34);
  EXPECT_EQ(reply->transaction_id, 0x1234);
  EXPECT_EQ(reply->instruction & 0x3F, command->instruction & 0x3F);
  ASSERT_EQ(reply->reply_spw_address.size(), 1U);
  EXPECT_EQ(reply->reply_spw_address.front(), 0x00);
}

TEST(SpwRmapTCPNodeImplTest, TargetWriteReplyCopiesCommandFields) {
  TestNode node(MakeNodeConfig());
  bool callback_called = false;
  node.RegisterOnWrite(
      [&callback_called](spw_rmap::Packet) -> void { callback_called = true; });
  const std::array<uint8_t, 4> reply_route{0x01, 0x02, 0x03, 0x04};
  const std::array<uint8_t, 1> data{0x5A};
  auto command_frame = BuildWriteCommandFrame(0x2345, data, reply_route, 0xA6,
                                              true, false, false);
  auto command =
      spw_rmap::ParseRMAPPacket(std::span(command_frame).subspan(12));
  ASSERT_TRUE(command.has_value());
  node.EnqueueIncoming(command_frame);

  ASSERT_TRUE(node.Poll().has_value());

  EXPECT_TRUE(callback_called);
  ASSERT_EQ(node.SentFrames().size(), 1U);
  auto reply = spw_rmap::ParseRMAPPacket(
      std::span(node.SentFrames().front()).subspan(12));
  ASSERT_TRUE(reply.has_value());
  EXPECT_EQ(reply->type, spw_rmap::PacketType::kWriteReply);
  EXPECT_EQ(reply->initiator_logical_address, 0xA6);
  EXPECT_EQ(reply->target_logical_address, 0x34);
  EXPECT_EQ(reply->transaction_id, 0x2345);
  EXPECT_EQ(reply->instruction & 0x3F, command->instruction & 0x3F);
  EXPECT_TRUE(std::ranges::equal(reply->reply_spw_address, reply_route));
}

TEST(SpwRmapTCPNodeImplTest, TargetDoesNotReplyToUnacknowledgedWrite) {
  TestNode node(MakeNodeConfig());
  bool callback_called = false;
  node.RegisterOnWrite(
      [&callback_called](spw_rmap::Packet) -> void { callback_called = true; });
  const std::array<uint8_t, 1> data{0x5A};
  node.EnqueueIncoming(BuildWriteCommandFrame(0x3456, data, {}, 0xA7, false));

  ASSERT_TRUE(node.Poll().has_value());

  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(node.SentFrames().empty());
}

TEST(SpwRmapTCPNodeImplTest, EmitTimecodeMasksUpperBits) {
  TestNode node(MakeNodeConfig());

  ASSERT_TRUE(node.EmitTimeCode(0xD5).has_value());

  ASSERT_EQ(node.SentFrames().size(), 1U);
  const auto& frame = node.SentFrames().front();
  ASSERT_EQ(frame.size(), 14U);
  EXPECT_EQ(frame[11], 0x02);
  EXPECT_EQ(frame[12], 0x15);
  EXPECT_EQ(frame[13], 0x00);
}

TEST(SpwRmapTCPNodeImplTest,
     ConcurrentRequestsAndTimecodesSerializeOutgoingFrames) {
  TestNode node(MakeNodeConfig());
  const auto target_node = spw_rmap::TargetNode(0x34);
  const std::array<uint8_t, 1> data{0x42};
  constexpr std::size_t kOperationsPerThread = 64;
  std::atomic<std::size_t> failures{0};

  auto submit_requests = [&]() -> void {
    for (std::size_t i = 0; i < kOperationsPerThread; ++i) {
      auto result = node.WriteAsync(target_node, 0x1000, data, [](auto) {});
      if (!result.has_value()) {
        ++failures;
      }
    }
  };
  auto emit_timecodes = [&]() -> void {
    for (std::size_t i = 0; i < kOperationsPerThread; ++i) {
      if (!node.EmitTimeCode(static_cast<uint8_t>(i)).has_value()) {
        ++failures;
      }
    }
  };

  std::thread first_request_thread(submit_requests);
  std::thread second_request_thread(submit_requests);
  std::thread timecode_thread(emit_timecodes);
  first_request_thread.join();
  second_request_thread.join();
  timecode_thread.join();

  EXPECT_EQ(failures.load(), 0U);
  EXPECT_EQ(node.SentFrames().size(), kOperationsPerThread * 3);
}

TEST(SpwRmapTCPNodeImplTest, WriteTimeoutReleasesTransactionId) {
  TestNode node(MakeNodeConfig());
  auto target_node = spw_rmap::TargetNode(0x34)
                         .SetTargetAddress(0x02, 0x03)
                         .SetReplyAddress(0x10, 0x11);
  std::array<uint8_t, 2> payload{0x01, 0x02};

  auto timeout_result =
      node.Write(target_node, 0x2000, payload, std::chrono::milliseconds(1));
  ASSERT_FALSE(timeout_result.has_value());
  EXPECT_EQ(timeout_result.error(), std::make_error_code(std::errc::timed_out));

  std::atomic<bool> callback_called{false};
  auto write_res = node.WriteAsync(
      target_node, 0x2000, payload,
      [&callback_called](std::expected<spw_rmap::Packet, std::error_code>)
          -> void { callback_called = true; });

  ASSERT_TRUE(write_res.has_value());
  auto transaction_id = write_res.value();

  node.EnqueueIncoming(BuildWriteReplyFrame(transaction_id));

  auto poll_result = node.Poll();
  ASSERT_TRUE(poll_result.has_value());

  EXPECT_TRUE(callback_called.load());
}

}  // namespace
