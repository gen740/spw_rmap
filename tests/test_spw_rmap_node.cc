#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <expected>
#include <mutex>
#include <span>
#include <vector>

#include "spw_rmap/internal/spw_rmap_tcp_node_impl.hh"
#include "spw_rmap/packet_builder.hh"
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
    sent_frames_.emplace_back(data.begin(), data.end());
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

  auto Shutdown() noexcept -> std::expected<void, std::error_code> override {
    return Backend().Shutdown();
  }

  auto IsShutdowned() noexcept -> bool override {
    return Backend().IsShutdown();
  }

 private:
  using Base::GetBackend;

  auto Backend() -> MockBackend& { return *GetBackend(); }
};

auto MakeFrame(std::span<const uint8_t> payload) -> std::vector<uint8_t> {
  std::vector<uint8_t> frame(12 + payload.size());
  frame[0] = 0x00;
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

auto BuildWriteReplyFrame(uint16_t transaction_id) -> std::vector<uint8_t> {
  auto reply_addr = std::array<uint8_t, 1>{0x01};
  auto config = spw_rmap::WriteReplyPacketConfig{
      .reply_spw_address = reply_addr,
      .initiator_logical_address = 0x34,
      .target_logical_address = 0xFE,
      .transaction_id = transaction_id,
      .status = spw_rmap::PacketStatusCode::kCommandExecutedSuccessfully,
      .increment_mode = true,
      .verify_mode = true,
  };
  std::vector<uint8_t> payload(config.ExpectedSize());
  EXPECT_TRUE(spw_rmap::BuildWriteReplyPacket(config, payload).has_value());
  return MakeFrame(payload);
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
                         .SetTargetAddress(0x20, 0x30)
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

TEST(SpwRmapTCPNodeImplTest, WriteTimeoutReleasesTransactionId) {
  TestNode node(MakeNodeConfig());
  auto target_node = spw_rmap::TargetNode(0x34)
                         .SetTargetAddress(0x20, 0x30)
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
