// Copyright (c) 2025 Gen
// Licensed under the MIT License. See LICENSE file for details.
#pragma once
#include <algorithm>
#include <chrono>
#include <concepts>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "spw_rmap/internal/debug.hh"
#include "spw_rmap/packet_builder.hh"
#include "spw_rmap/packet_parser.hh"
#include "spw_rmap/spw_rmap_node_base.hh"

namespace spw_rmap {

using namespace std::chrono_literals;

enum class BufferPolicy : uint8_t {
  kFixed,       // Fixed size
  kAutoResize,  // Auto resize if needed
};

struct SpwRmapTCPNodeConfig {
  std::string ip_address;  // Expect Small String optimization
  std::string port;
  size_t send_buffer_size = 4096;
  size_t recv_buffer_size = 4096;
  size_t send_pool_size = 4;
  size_t recv_pool_size = 4;
  uint16_t transaction_id_min = 0x0000;
  uint16_t transaction_id_max = 0x00FF;
  BufferPolicy buffer_policy = BufferPolicy::kAutoResize;
  std::chrono::microseconds send_timeout = std::chrono::milliseconds{500};
};

namespace internal {
template <class B>
concept TcpBackend = requires(
    B b, std::string ip, std::string port, std::chrono::microseconds us,
    std::span<uint8_t> inbuf, std::span<const uint8_t> outbuf) {
  { B(ip, port) };
  { b.GetIpAddress() } -> std::same_as<const std::string&>;
  { b.SetIpAddress(std::move(ip)) } -> std::same_as<void>;
  { b.GetPort() } -> std::same_as<const std::string&>;
  { b.SetPort(std::move(port)) } -> std::same_as<void>;
  {
    b.SetSendTimeout(us)
  } -> std::same_as<std::expected<void, std::error_code>>;
  {
    b.SetReceiveTimeout(us)
  } -> std::same_as<std::expected<void, std::error_code>>;
  { b.RecvSome(inbuf) } -> std::same_as<std::expected<size_t, std::error_code>>;
  { b.SendAll(outbuf) } -> std::same_as<std::expected<void, std::error_code>>;
  { b.EnsureConnect() } -> std::same_as<std::expected<void, std::error_code>>;
};

template <TcpBackend Backend>
class SpwRmapTCPNodeImpl : public SpwRmapNodeBase {
 private:
  std::unique_ptr<Backend> tcp_backend_ = nullptr;

  std::vector<uint8_t> recv_buf_ = {};
  std::vector<uint8_t> send_buf_ = {};
  BufferPolicy buffer_policy_ = BufferPolicy::kAutoResize;
  std::chrono::microseconds send_timeout_{std::chrono::milliseconds{500}};

  std::atomic<bool> running_{false};

  std::function<void(Packet)> on_write_callback_ = [](Packet) noexcept -> void {
    // No-op
  };
  std::function<std::vector<uint8_t>(Packet)> on_read_callback_ =
      [](Packet packet) noexcept -> std::vector<uint8_t> {
    std::vector<uint8_t> empty;
    empty.resize(packet.data_length);
    return empty;
  };
  std::function<void(uint8_t)> on_timecode_callback_ = nullptr;

  std::atomic<bool> auto_polling_mode_{false};

  std::mutex send_mtx_;
  mutable std::mutex auto_polling_serial_mtx_;

  SpwRmapTCPNodeConfig config_;

 public:
  explicit SpwRmapTCPNodeImpl(SpwRmapTCPNodeConfig config) noexcept
      : SpwRmapNodeBase(config.transaction_id_min, config.transaction_id_max),
        tcp_backend_(std::make_unique<Backend>(config.ip_address, config.port)),
        recv_buf_(config.recv_buffer_size),
        send_buf_(config.send_buffer_size),
        buffer_policy_(config.buffer_policy),
        send_timeout_(config.send_timeout),
        config_(config) {}

  auto EnsureTcpConnection() noexcept -> std::expected<void, std::error_code> {
    return tcp_backend_->EnsureConnect().and_then(
        [this]() -> std::expected<void, std::error_code> {
          return tcp_backend_->SetSendTimeout(send_timeout_);
        });
  }

  auto GetConfig() const noexcept -> const SpwRmapTCPNodeConfig& {
    return config_;
  }

 protected:
  auto GetBackend() noexcept -> std::unique_ptr<Backend>& {
    return tcp_backend_;
  }

  auto GetIpAddress() const noexcept -> const std::string& {
    return tcp_backend_->GetIpAddress();
  }

  auto SetIpAddress(std::string ip_address) noexcept -> void {
    tcp_backend_->SetIpAddress(std::move(ip_address));
  }

  auto GetPort() const noexcept -> const std::string& {
    return tcp_backend_->GetPort();
  }

  auto SetPort(std::string port) noexcept -> void {
    tcp_backend_->SetPort(std::move(port));
  }

  auto GetSendTimeout() const noexcept -> std::chrono::microseconds {
    return send_timeout_;
  }

  auto SetSendTimeoutInternal(std::chrono::microseconds timeout) noexcept
      -> std::expected<void, std::error_code> {
    if (timeout < std::chrono::microseconds::zero()) [[unlikely]] {
      return std::unexpected{std::make_error_code(std::errc::invalid_argument)};
    }
    send_timeout_ = timeout;
    return tcp_backend_->SetSendTimeout(timeout);
  }

  auto ConnectLoopUntilHealthy() noexcept
      -> std::expected<void, std::error_code> {
    std::error_code last_error = std::make_error_code(std::errc::not_connected);
    constexpr int kMaxAttempts = 3;
    for (int attempt = 0; attempt < kMaxAttempts && running_.load();
         ++attempt) {
      auto res = EnsureTcpConnection();
      if (res.has_value()) [[likely]] {
        return res;
      }
      last_error = res.error();
      std::this_thread::sleep_for(std::chrono::milliseconds{100});
    }
    return std::unexpected{last_error};
  }

 private:
  auto RecvExact(std::span<uint8_t> buffer)
      -> std::expected<std::size_t, std::error_code> {
    size_t total_length = buffer.size();
    while (!buffer.empty()) {
      auto res = tcp_backend_->RecvSome(buffer);
      if (!res.has_value()) [[unlikely]] {
        return std::unexpected(res.error());
      }
      if (res.value() == 0) [[unlikely]] {
        return 0;
      }
      buffer = buffer.subspan(res.value());
    }
    return total_length;
  }

  static inline auto CalculateDataLengthFromHeader(
      const std::span<const uint8_t> header) noexcept
      -> std::expected<size_t, std::error_code> {
    if (header.size() < 12) [[unlikely]] {
      spw_rmap::debug::Debug("Header size less than 12 bytes");
      return std::unexpected{std::make_error_code(std::errc::invalid_argument)};
    }
    std::ignore /* extra_length */ = (static_cast<uint16_t>(header[2]) << 8) |
                                     (static_cast<uint16_t>(header[3]) << 0);
    uint64_t data_length = ((static_cast<uint64_t>(header[4]) << 56) |
                            (static_cast<uint64_t>(header[5]) << 48) |
                            (static_cast<uint64_t>(header[6]) << 40) |
                            (static_cast<uint64_t>(header[7]) << 32) |
                            (static_cast<uint64_t>(header[8]) << 24) |
                            (static_cast<uint64_t>(header[9]) << 16) |
                            (static_cast<uint64_t>(header[10]) << 8) |
                            (static_cast<uint64_t>(header[11]) << 0));
    return data_length;
  }

  struct AsyncOperation {
    std::future<std::expected<void, std::error_code>> future;
    std::optional<uint16_t> transaction_id;
  };

  using PromiseType = std::promise<std::expected<void, std::error_code>>;

  auto RecvAndParseOnePacket() noexcept
      -> std::expected<Packet, std::error_code> {
    size_t total_size = 0;
    auto eof = false;
    auto recv_buffer = std::span(recv_buf_);
    while (!eof) {
      std::array<uint8_t, 12> header{};
      auto res = RecvExact(header);
      if (!res.has_value()) [[unlikely]] {
        return std::unexpected(res.error());
      }
      if (res.value() == 0) [[unlikely]] {
        return std::unexpected{
            std::make_error_code(std::errc::connection_aborted)};
      }
      if (header[0] != 0x00 && header[0] != 0x01 && header[0] != 0x02 &&
          header[0] != 0x31 && header[0] != 0x30) [[unlikely]] {
        spw_rmap::debug::Debug("Received packet with invalid type byte: ",
                               static_cast<int>(header[0]));
        return std::unexpected{std::make_error_code(std::errc::bad_message)};
      }
      if (header[1] != 0x00) [[unlikely]] {
        spw_rmap::debug::Debug("Received packet with invalid reserved byte: ",
                               static_cast<int>(header[1]));
        return std::unexpected{std::make_error_code(std::errc::bad_message)};
      }

      auto data_length = CalculateDataLengthFromHeader(header);
      if (!data_length.has_value()) [[unlikely]] {
        spw_rmap::debug::Debug("Failed to calculate data length from header");
        return std::unexpected(data_length.error());
      }
      if (*data_length == 0) [[unlikely]] {
        spw_rmap::debug::Debug("Received packet with zero data length");
        return std::unexpected{std::make_error_code(std::errc::bad_message)};
      }
      if (*data_length > recv_buffer.size()) [[unlikely]] {
        if (buffer_policy_ == BufferPolicy::kFixed) {
          spw_rmap::debug::Debug(
              "Receive buffer too small for incoming packet data");
          return std::unexpected{
              std::make_error_code(std::errc::no_buffer_space)};
        } else {
          recv_buf_.resize(total_size + *data_length);
          recv_buffer = std::span(recv_buf_).subspan(total_size);
        }
      }
      switch (header[0]) {
        case 0x00: {
          auto res = RecvExact(recv_buffer.first(*data_length));
          if (!res.has_value()) [[unlikely]] {
            spw_rmap::debug::Debug(
                "Failed to receive packet data of type 0x00");
            return std::unexpected(res.error());
          }
          total_size += *res;
          eof = true;
        } break;
        case 0x01:
          [[unlikely]] {
            auto res = IgnoreNBytes(*data_length);
            if (!res.has_value()) [[unlikely]] {
              spw_rmap::debug::Debug(
                  "Failed to ignore packet data of type 0x01");
              return std::unexpected(res.error());
            }
            return RecvAndParseOnePacket();
          }
          break;
        case 0x02:
          [[unlikely]] {
            auto res = RecvExact(recv_buffer.first(*data_length));
            if (!res.has_value()) [[unlikely]] {
              spw_rmap::debug::Debug(
                  "Failed to receive packet data of type 0x02");
              return std::unexpected(res.error());
            }
            total_size += *res;
            recv_buffer = recv_buffer.subspan(*data_length);
          }
          break;
        case 0x30:
        case 0x31: {
          // Timecode packet
          if (header[2] != 0x00 || header[3] != 0x00 || header[4] != 0x00 ||
              header[5] != 0x00 || header[6] != 0x00 || header[7] != 0x00 ||
              header[8] != 0x00 || header[9] != 0x00 || header[10] != 0x00 ||
              header[11] != 0x02) [[unlikely]] {
            spw_rmap::debug::Debug("Received invalid Timecode packet header");
            return std::unexpected{
                std::make_error_code(std::errc::bad_message)};
          }
          std::array<uint8_t, 2> tc{};
          auto res = RecvExact(tc);
          if (!res.has_value()) [[unlikely]] {
            spw_rmap::debug::Debug("Failed to receive Timecode packet data");
            return std::unexpected(res.error());
          }
          if (tc[1] != 0x00) [[unlikely]] {
            spw_rmap::debug::Debug("Received invalid Timecode packet data");
            return std::unexpected{
                std::make_error_code(std::errc::bad_message)};
          }
          on_timecode_callback_(tc[0] & 0x3F);
        } break;
        default:
          spw_rmap::debug::Debug("Received packet with unknown type byte: ",
                                 static_cast<int>(header[0]));
          return std::unexpected{std::make_error_code(std::errc::bad_message)};
      }
    }
    return ParseRMAPPacket(std::span(recv_buf_).first(total_size));
  }

  auto IgnoreNBytes(std::size_t n)
      -> std::expected<std::size_t, std::error_code> {
    const size_t requested_size = n;
    std::array<uint8_t, 16> ignore_buffer{};
    while (n > ignore_buffer.size()) {
      auto res = tcp_backend_->RecvSome(ignore_buffer);
      if (!res.has_value()) [[unlikely]] {
        spw_rmap::debug::Debug("Failed to receive data to ignore");
        return std::unexpected{res.error()};
      }
      if (res.value() == 0) [[unlikely]] {
        spw_rmap::debug::Debug("Connection closed while ignoring data");
        return std::unexpected{
            std::make_error_code(std::errc::connection_aborted)};
      }
      n -= res.value();
    }
    if (n > 0) [[likely]] {
      auto res = RecvExact(std::span(ignore_buffer).first(n));
      if (!res.has_value()) [[unlikely]] {
        spw_rmap::debug::Debug("Failed to receive data to ignore");
        return std::unexpected{res.error()};
      }
    }
    return requested_size;
  }

  auto SetHeader(size_t total_size) noexcept -> void {
    send_buf_[0] = 0x00;
    send_buf_[1] = 0x00;
    send_buf_[2] = 0x00;
    send_buf_[3] = 0x00;
    send_buf_[4] = static_cast<uint8_t>((total_size >> 56) & 0xFF);
    send_buf_[5] = static_cast<uint8_t>((total_size >> 48) & 0xFF);
    send_buf_[6] = static_cast<uint8_t>((total_size >> 40) & 0xFF);
    send_buf_[7] = static_cast<uint8_t>((total_size >> 32) & 0xFF);
    send_buf_[8] = static_cast<uint8_t>((total_size >> 24) & 0xFF);
    send_buf_[9] = static_cast<uint8_t>((total_size >> 16) & 0xFF);
    send_buf_[10] = static_cast<uint8_t>((total_size >> 8) & 0xFF);
    send_buf_[11] = static_cast<uint8_t>((total_size >> 0) & 0xFF);
  }

  auto SendReadPacket(const TargetNode& target_node, uint16_t transaction_id,
                      uint32_t memory_address, uint32_t data_length) noexcept
      -> std::expected<void, std::error_code> {
    std::lock_guard<std::mutex> lock(send_mtx_);
    auto config = ReadPacketConfig{
        .target_spw_address = target_node.GetTargetAddress(),
        .target_logical_address = target_node.GetTargetLogicalAddress(),
        .reply_address = target_node.GetReplyAddress(),
        .initiator_logical_address = GetInitiatorLogicalAddress(),
        .transaction_id = transaction_id,
        .extended_address = 0x00,
        .address = memory_address,
        .data_length = data_length,
    };
    auto send_buffer = std::span(send_buf_);
    if (config.ExpectedSize() + 12 > send_buffer.size()) [[unlikely]] {
      if (buffer_policy_ == BufferPolicy::kFixed) {
        spw_rmap::debug::Debug("Send buffer too small for Read Packet");
        return std::unexpected{
            std::make_error_code(std::errc::no_buffer_space)};
      } else {
        send_buf_.resize(config.ExpectedSize() + 12);
        send_buffer = std::span(send_buf_);
      }
    }

    auto res = spw_rmap::BuildReadPacket(config, send_buffer.subspan(12));
    if (!res.has_value()) [[unlikely]] {
      spw_rmap::debug::Debug("Failed to build Read Packet: ",
                             res.error().message());
      return std::unexpected{res.error()};
    }
    if (send_buffer.size() < config.ExpectedSize() + 12) [[unlikely]] {
      if (buffer_policy_ == BufferPolicy::kFixed) {
        spw_rmap::debug::Debug("Send buffer too small for Read Packet");
        return std::unexpected{
            std::make_error_code(std::errc::no_buffer_space)};
      } else {
        send_buf_.resize(config.ExpectedSize() + 12);
        send_buffer = std::span(send_buf_);
      }
    }
    SetHeader(config.ExpectedSize());
    return tcp_backend_->SendAll(
        std::span(send_buf_).first(config.ExpectedSize() + 12));
  }

  auto SendWritePacket(const TargetNode& target_node, uint16_t transaction_id,
                       uint32_t memory_address,
                       const std::span<const uint8_t> data) noexcept
      -> std::expected<void, std::error_code> {
    std::lock_guard<std::mutex> lock(send_mtx_);
    auto config = WritePacketConfig{
        .target_spw_address = target_node.GetTargetAddress(),
        .target_logical_address = target_node.GetTargetLogicalAddress(),
        .reply_address = target_node.GetReplyAddress(),
        .initiator_logical_address = GetInitiatorLogicalAddress(),
        .transaction_id = transaction_id,
        .extended_address = 0x00,
        .address = memory_address,
        .verify_mode = IsVerifyMode(),
        .data = data,
    };
    auto send_buffer = std::span(send_buf_);
    if (config.ExpectedSize() + 12 > send_buffer.size()) [[unlikely]] {
      if (buffer_policy_ == BufferPolicy::kFixed) {
        spw_rmap::debug::Debug("Send buffer too small for Write Packet");
        return std::unexpected{
            std::make_error_code(std::errc::no_buffer_space)};
      } else {
        send_buf_.resize(config.ExpectedSize() + 12);
        send_buffer = std::span(send_buf_);
      }
    }
    auto res = spw_rmap::BuildWritePacket(config, send_buffer.subspan(12));
    if (!res.has_value()) [[unlikely]] {
      spw_rmap::debug::Debug("Failed to build Write Packet: ",
                             res.error().message());
      return std::unexpected{res.error()};
    }
    SetHeader(config.ExpectedSize());
    return tcp_backend_->SendAll(
        std::span(send_buf_).first(config.ExpectedSize() + 12));
  }

  auto SendReadReplyPacket(Packet packet, const std::vector<uint8_t>& data)
      -> std::expected<void, std::error_code> {
    if (data.size() != packet.data_length) [[unlikely]] {
      std::cerr << "on_read_callback_ returned data with incorrect length: "
                << data.size() << " (expected " << packet.data_length << ")\n";
      return std::unexpected{std::make_error_code(std::errc::invalid_argument)};
    }
    auto config = ReadReplyPacketConfig{
        .reply_spw_address = packet.reply_address,
        .initiator_logical_address = packet.target_logical_address,
        .target_logical_address = packet.initiator_logical_address,
        .transaction_id = packet.transaction_id,
        .status = PacketStatusCode::kCommandExecutedSuccessfully,
        .increment_mode = true,
        .data = data,
    };
    std::lock_guard<std::mutex> lock(send_mtx_);
    auto send_buffer = std::span(send_buf_);
    if (config.ExpectedSize() + 12 > send_buffer.size()) [[unlikely]] {
      if (buffer_policy_ == BufferPolicy::kFixed) {
        spw_rmap::debug::Debug("Send buffer too small for Read Reply Packet");
        return std::unexpected{
            std::make_error_code(std::errc::no_buffer_space)};
      }
      send_buf_.resize(config.ExpectedSize() + 12);
      send_buffer = std::span(send_buf_);
    }
    auto build_res =
        spw_rmap::BuildReadReplyPacket(config, send_buffer.subspan(12));
    if (!build_res.has_value()) [[unlikely]] {
      spw_rmap::debug::Debug("Failed to build Read Reply Packet: ",
                             build_res.error().message());
      return std::unexpected{build_res.error()};
    }
    SetHeader(config.ExpectedSize());
    return tcp_backend_->SendAll(
        std::span(send_buf_).first(config.ExpectedSize() + 12));
  }

  auto SendWriteReplyPacket(Packet packet)
      -> std::expected<void, std::error_code> {
    auto config = WriteReplyPacketConfig{
        .reply_spw_address = packet.reply_address,
        .initiator_logical_address = packet.target_logical_address,
        .target_logical_address = packet.initiator_logical_address,
        .transaction_id = packet.transaction_id,
        .status = PacketStatusCode::kCommandExecutedSuccessfully,
        .increment_mode = true,
        .verify_mode = true,
    };
    std::lock_guard<std::mutex> lock(send_mtx_);
    auto send_buffer = std::span(send_buf_);
    if (config.ExpectedSize() + 12 > send_buffer.size()) [[unlikely]] {
      if (buffer_policy_ == BufferPolicy::kFixed) {
        spw_rmap::debug::Debug("Send buffer too small for Write Reply Packet");
        return std::unexpected{
            std::make_error_code(std::errc::no_buffer_space)};
      }
      send_buf_.resize(config.ExpectedSize() + 12);
      send_buffer = std::span(send_buf_);
    }
    auto build_res =
        spw_rmap::BuildWriteReplyPacket(config, send_buffer.subspan(12));
    if (!build_res.has_value()) [[unlikely]] {
      std::cerr << "Failed to build Write Reply Packet: "
                << build_res.error().message() << "\n";
      return std::unexpected{build_res.error()};
    }
    SetHeader(config.ExpectedSize());
    return tcp_backend_->SendAll(
        std::span(send_buf_).first(config.ExpectedSize() + 12));
  }

 public:
  virtual auto Shutdown() noexcept -> std::expected<void, std::error_code> = 0;

  virtual auto IsShutdowned() noexcept -> bool = 0;

  auto Poll() noexcept -> std::expected<void, std::error_code> override {
    return RecvAndParseOnePacket()
        .and_then([this](
                      Packet packet) -> std::expected<void, std::error_code> {
          switch (packet.type) {
            case PacketType::kReadReply:
            case PacketType::kWriteReply: {
              if (!GetTransactionDatabase().Contains(packet.transaction_id))
                  [[unlikely]] {
                spw_rmap::debug::Debug(
                    "Received packet with out-of-range Transaction ID: ",
                    packet.transaction_id);
                return std::unexpected{
                    std::make_error_code(std::errc::bad_message)};
              }
              const auto handled = GetTransactionDatabase().InvokeReplyCallback(
                  packet.transaction_id, packet);
              if (!handled) [[unlikely]] {
                std::cerr << "No callback registered for Transaction ID: "
                          << packet.transaction_id << "\n";
              }
              return {};
            }
            case PacketType::kRead: {
              if (on_read_callback_) [[likely]] {
#ifdef __EXCEPTIONS
                try {
                  return SendReadReplyPacket(packet, on_read_callback_(packet));
                } catch (const std::exception& e) {
                  spw_rmap::debug::Debug("Exception in on_read_callback_: ",
                                         e.what());
                  return std::unexpected{
                      std::make_error_code(std::errc::operation_canceled)};
                }
#else
                return SendReadReplyPacket(packet, on_read_callback_(packet));
#endif
              }
              return {};
            }
            case PacketType::kWrite: {
              if (on_write_callback_) [[likely]] {
#ifdef __EXCEPTIONS
                try {
                  on_write_callback_(packet);
                  return SendWriteReplyPacket(packet);
                } catch (const std::exception& e) {
                  spw_rmap::debug::Debug("Exception in on_write_callback_: ",
                                         e.what());
                  return std::unexpected{
                      std::make_error_code(std::errc::operation_canceled)};
                }
#else
                on_write_callback_(packet);
                return SendWriteReplyPacket(packet);
#endif
              }
              return {};
            }
            default:
              return {};
          }
        })
        .or_else(
            [](std::error_code ec) -> std::expected<void, std::error_code> {
              spw_rmap::debug::Debug("Error in receiving/parsing packet: ",
                                     ec.message());
              return std::unexpected{ec};
            });
  }

  auto RunLoop() noexcept -> std::expected<void, std::error_code> override {
    running_.store(true);
    while (running_.load()) {
      auto res = Poll();
      if (res.has_value()) [[likely]] {
        continue;
      }
      spw_rmap::debug::Debug("Error in poll(): ", res.error().message());
      auto ensure_res = EnsureTcpConnection();
      if (ensure_res.has_value()) [[likely]] {
        continue;
      }
      auto reconnect_res = ConnectLoopUntilHealthy();
      if (!reconnect_res.has_value()) [[unlikely]] {
        running_.store(false);
        return std::unexpected{reconnect_res.error()};
      }
    }
    return {};
  }

  auto RegisterOnWrite(std::function<void(Packet)> on_write) noexcept
      -> void override {
    on_write_callback_ = std::move(on_write);
  }

  auto RegisterOnRead(
      std::function<std::vector<uint8_t>(Packet)> on_read) noexcept
      -> void override {
    on_read_callback_ = std::move(on_read);
  }

  auto RegisterOnTimeCode(std::function<void(uint8_t)> on_time_code) noexcept
      -> void override {
    on_timecode_callback_ = std::move(on_time_code);
  }

  /**
   * @brief Enables or disables auto polling.
   *
   * When enabled, the node runs `poll()` internally; synchronous `read`/`write`
   * must be issued one at a time and the asynchronous APIs (`readAsync`,
   * `writeAsync`) return `operation_not_permitted`.
   */
  auto SetAutoPollingMode(bool enable) noexcept -> void {
    auto_polling_mode_ = enable;
  }

  /**
   * @brief Synchronously write data to a target node.
   *
   * When auto polling mode is enabled via `setAutoPollingMode(true)` this call
   * must be serialized; do not issue concurrent synchronous writes because the
   * internal poll loop can only track one outstanding transaction at a time in
   * that mode.
   */
  auto Write(const TargetNode& target_node, uint32_t memory_address,
             const std::span<const uint8_t> data,
             std::chrono::milliseconds timeout =
                 std::chrono::milliseconds{100}) noexcept
      -> std::expected<void, std::error_code> override {
    if (auto_polling_mode_) {
      std::unique_lock<std::mutex> autopoll_lock(auto_polling_serial_mtx_);
      int32_t transaction_id_memo = -1;
      return EnsureTcpConnection()
          .and_then([this, timeout]() -> std::expected<void, std::error_code> {
            return tcp_backend_->SetReceiveTimeout(timeout);
          })
          .and_then([this]() -> std::expected<uint16_t, std::error_code> {
            return AcquireTransaction();
          })
          .and_then([this, &target_node, &memory_address, &data,
                     &transaction_id_memo](uint16_t transaction_id)
                        -> std::expected<void, std::error_code> {
            transaction_id_memo = transaction_id;
            return SendWritePacket(target_node, transaction_id, memory_address,
                                   data);
          })
          .and_then([this]() -> std::expected<Packet, std::error_code> {
            return RecvAndParseOnePacket();
          })
          .and_then([this, &transaction_id_memo](
                        Packet packet) -> std::expected<void, std::error_code> {
            if (packet.transaction_id !=
                static_cast<uint16_t>(transaction_id_memo)) [[unlikely]] {
              spw_rmap::debug::Debug(
                  "Received packet with unexpected Transaction ID: ",
                  packet.transaction_id);
              return std::unexpected{make_error_code(std::errc::bad_message)};
            }
            if (packet.type == PacketType::kWriteReply) [[likely]] {
              CancelTransaction(static_cast<uint16_t>(transaction_id_memo));
              return {};
            } else {
              return std::unexpected{
                  std::make_error_code(std::errc::bad_message)};
            }
          })
          .or_else([this, &transaction_id_memo](std::error_code ec)
                       -> std::expected<void, std::error_code> {
            if (transaction_id_memo >= 0) [[likely]] {
              CancelTransaction(static_cast<uint16_t>(transaction_id_memo));
            }
            return std::unexpected{ec};
          });
    } else {
      auto write_res = std::expected<void, std::error_code>{};
      std::mutex write_mtx;
      std::condition_variable write_cv;
      bool write_completed = false;
      return WriteAsync(target_node, memory_address, data,
                        [&write_res, &write_completed, &write_mtx, &write_cv](
                            std::expected<Packet, std::error_code> res) noexcept
                            -> void {
                          {
                            std::unique_lock<std::mutex> lock(write_mtx);
                            write_res = res.transform(
                                [](const Packet&) noexcept -> void {});
                            write_completed = true;
                          }
                          write_cv.notify_one();
                        })
          .and_then([this, &write_res, &write_completed, &write_mtx, &write_cv,
                     timeout](uint16_t transaction_id) noexcept
                        -> std::expected<void, std::error_code> {
            std::unique_lock<std::mutex> lock(write_mtx);
            if (write_cv.wait_for(lock, ClampTransactionTimeout(timeout),
                                  [&write_completed] -> auto {
                                    return write_completed;
                                  })) [[likely]] {
              return write_res;
            }
            CancelTransaction(transaction_id);
            return std::unexpected{std::make_error_code(std::errc::timed_out)};
          });
    }
  }

  /**
   * @brief Asynchronously write data to a target node.
   *
   * Auto polling mode disables asynchronous writes—`writeAsync` immediately
   * returns a future containing `operation_not_permitted` when
   * `setAutoPollingMode(true)` is active.
   */
  auto WriteAsync(const TargetNode& target_node, uint32_t memory_address,
                  const std::span<const uint8_t> data,
                  std::function<void(std::expected<Packet, std::error_code>)>
                      on_complete) noexcept
      -> std::expected<uint16_t, std::error_code> override {
    if (auto_polling_mode_) [[unlikely]] {
      return std::unexpected{
          std::make_error_code(std::errc::operation_not_permitted)};
    }
    return AcquireTransaction([on_complete = std::move(on_complete)](
                                  std::expected<Packet, std::error_code>
                                      result) mutable noexcept -> void {
#ifdef __EXCEPTIONS
             try {
               on_complete(std::move(result));
             } catch (const std::exception& e) {
               spw_rmap::debug::Debug("Exception in writeAsync callback: ",
                                      e.what());
             } catch (...) {
               spw_rmap::debug::Debug(
                   "Unknown exception in writeAsync callback");
             }
#else
             on_complete(std::move(result));
#endif
           })
        .and_then([this, &target_node, memory_address,
                   data](uint16_t transaction_id) noexcept
                      -> std::expected<uint16_t, std::error_code> {
          return SendWritePacket(target_node, transaction_id, memory_address,
                                 data)
              .transform_error(
                  [this, transaction_id](
                      std::error_code ec) noexcept -> std::error_code {
                    CancelTransaction(transaction_id);
                    return ec;
                  })
              .transform([transaction_id]() noexcept -> uint16_t {
                return transaction_id;
              });
        });
  }

  /**
   * @brief Synchronously read data from a target node.
   *
   * With auto polling enabled only one synchronous read may be in flight—wait
   * for the call to finish before issuing another synchronous read/write.
   */
  auto Read(const TargetNode& target_node, uint32_t memory_address,
            const std::span<uint8_t> data,
            std::chrono::milliseconds timeout =
                std::chrono::milliseconds{100}) noexcept
      -> std::expected<void, std::error_code> override {
    if (auto_polling_mode_) {
      std::unique_lock<std::mutex> autopoll_lock(auto_polling_serial_mtx_);
      int32_t transaction_id_memo = -1;
      return EnsureTcpConnection()
          .and_then([this, timeout]() -> std::expected<void, std::error_code> {
            return tcp_backend_->SetReceiveTimeout(timeout);
          })
          .and_then([this]() -> std::expected<uint16_t, std::error_code> {
            return AcquireTransaction();
          })
          .and_then([this, &target_node, &memory_address, &data,
                     &transaction_id_memo](uint16_t transaction_id)
                        -> std::expected<void, std::error_code> {
            transaction_id_memo = transaction_id;
            return SendReadPacket(target_node, transaction_id, memory_address,
                                  data.size())
                .transform_error(
                    [this, transaction_id](
                        std::error_code ec) noexcept -> std::error_code {
                      CancelTransaction(transaction_id);
                      return ec;
                    });
          })
          .and_then([this]() -> std::expected<Packet, std::error_code> {
            return RecvAndParseOnePacket();
          })
          .and_then([this, &transaction_id_memo, &data](
                        Packet packet) -> std::expected<void, std::error_code> {
            if (packet.transaction_id !=
                static_cast<uint16_t>(transaction_id_memo)) [[unlikely]] {
              spw_rmap::debug::Debug(
                  "Received packet with unexpected Transaction ID: ",
                  packet.transaction_id);
              return std::unexpected{
                  std::make_error_code(std::errc::bad_message)};
            }
            if (packet.type != PacketType::kReadReply) [[unlikely]] {
              return std::unexpected{
                  std::make_error_code(std::errc::bad_message)};
            }
            if (packet.data_length != data.size() ||
                packet.data.size() != data.size()) [[unlikely]] {
              spw_rmap::debug::Debug(
                  "Received Read Reply packet with unexpected data "
                  "length: ",
                  packet.data_length);
              return std::unexpected{
                  std::make_error_code(std::errc::bad_message)};
            }
            std::ranges::copy(packet.data, data.begin());
            CancelTransaction(static_cast<uint16_t>(transaction_id_memo));
            return {};
          })
          .or_else([this, &transaction_id_memo](std::error_code ec)
                       -> std::expected<void, std::error_code> {
            if (transaction_id_memo >= 0) [[likely]] {
              CancelTransaction(static_cast<uint16_t>(transaction_id_memo));
            }
            return std::unexpected{ec};
          });
    } else {
      auto read_res = std::expected<void, std::error_code>{};
      std::mutex read_mtx;
      std::condition_variable read_cv;
      bool read_completed = false;
      return ReadAsync(
                 target_node, memory_address,
                 static_cast<uint32_t>(data.size()),
                 [&data, &read_res, &read_completed, &read_mtx,
                  &read_cv](std::expected<Packet, std::error_code> res) noexcept
                     -> void {
                   {
                     std::unique_lock<std::mutex> lock(read_mtx);
                     read_res = res.and_then(
                         [&data](const Packet& packet) noexcept
                             -> std::expected<void, std::error_code> {
                           if (packet.data.size() != data.size()) [[unlikely]] {
                             return std::unexpected(
                                 std::make_error_code(std::errc::bad_message));
                           } else {
                             std::ranges::copy(packet.data, data.begin());
                           }
                           return {};
                         });
                     read_completed = true;
                   }
                   read_cv.notify_one();
                 })
          .and_then([this, &read_res, &read_completed, &read_mtx, &read_cv,
                     timeout](uint16_t transaction_id) noexcept
                        -> std::expected<void, std::error_code> {
            std::unique_lock<std::mutex> lock(read_mtx);
            if (read_cv.wait_for(lock, ClampTransactionTimeout(timeout),
                                 [&read_completed] -> auto {
                                   return read_completed;
                                 })) [[likely]] {
              return read_res;
            }
            CancelTransaction(transaction_id);
            return std::unexpected{std::make_error_code(std::errc::timed_out)};
          });
    }
  }

  /**
   * @brief Asynchronously read data from a target node.
   *
   * When auto polling mode is active this function is unavailable and returns a
   * future that resolves to `operation_not_permitted`.
   */
  auto ReadAsync(const TargetNode& target_node, uint32_t memory_address,
                 uint32_t data_length,
                 std::function<void(std::expected<Packet, std::error_code>)>
                     on_complete) noexcept
      -> std::expected<uint16_t, std::error_code> override {
    if (auto_polling_mode_) {
      return std::unexpected{
          std::make_error_code(std::errc::operation_not_permitted)};
    }
    return AcquireTransaction([on_complete = std::move(on_complete)](
                                  std::expected<Packet, std::error_code>
                                      result) mutable noexcept -> void {
#ifdef __EXCEPTIONS
             try {
               on_complete(std::move(result));
             } catch (const std::exception& e) {
               spw_rmap::debug::Debug("Exception in readAsync callback: ",
                                      e.what());
             } catch (...) {
               spw_rmap::debug::Debug(
                   "Unknown exception in readAsync callback");
             }
#else
             on_complete(std::move(result));
#endif
           })
        .and_then([this, &target_node, memory_address,
                   data_length](uint16_t transaction_id) noexcept
                      -> std::expected<uint16_t, std::error_code> {
          return SendReadPacket(target_node, transaction_id, memory_address,
                                data_length)
              .transform_error(
                  [this, transaction_id](
                      std::error_code ec) noexcept -> std::error_code {
                    CancelTransaction(transaction_id);
                    return ec;
                  })
              .transform([transaction_id]() noexcept -> uint16_t {
                return transaction_id;
              });
        });
  }

  auto EmitTimeCode(uint8_t timecode) noexcept
      -> std::expected<void, std::error_code> override {
    std::lock_guard<std::mutex> lock(send_mtx_);
    std::array<uint8_t, 14> packet{};
    packet[0] = 0x30;
    packet[11] = 0x02;  // reserved
    packet[12] = timecode;
    packet[13] = 0x00;
    return tcp_backend_->SendAll(packet);
  }
};

}  // namespace internal

}  // namespace spw_rmap
