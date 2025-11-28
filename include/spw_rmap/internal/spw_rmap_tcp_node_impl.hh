// Copyright (c) 2025 Gen
// Licensed under the MIT License. See LICENSE file for details.
#pragma once
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include "spw_rmap/error_code.hh"
#include "spw_rmap/internal/debug.hh"
#include "spw_rmap/internal/transaction_database.hh"
#include "spw_rmap/packet_builder.hh"
#include "spw_rmap/packet_parser.hh"
#include "spw_rmap/spw_rmap_node_base.hh"

namespace spw_rmap {

using namespace std::chrono_literals;

enum class BufferPolicy : uint8_t {
  Fixed,       // Fixed size
  AutoResize,  // Auto resize if needed
};

struct SpwRmapTCPNodeConfig {
  std::string ip_address;  // Expect Small String optimization
  std::string port;
  size_t send_buffer_size = 4096;
  size_t recv_buffer_size = 4096;
  size_t send_pool_size = 4;
  size_t recv_pool_size = 4;
  uint16_t transaction_id_min = 0x0020;
  uint16_t transaction_id_max = 0x0040;
  BufferPolicy buffer_policy = BufferPolicy::AutoResize;
  std::chrono::microseconds send_timeout = std::chrono::milliseconds{500};
};

namespace internal {
template <class B>
concept TcpBackend = requires(
    B b, std::string ip, std::string port, std::chrono::microseconds us,
    std::span<uint8_t> inbuf, std::span<const uint8_t> outbuf) {
  { B(ip, port) };
  { b.getIpAddress() } -> std::same_as<const std::string&>;
  { b.setIpAddress(std::move(ip)) } -> std::same_as<void>;
  { b.getPort() } -> std::same_as<const std::string&>;
  { b.setPort(std::move(port)) } -> std::same_as<void>;
  {
    b.setSendTimeout(us)
  } -> std::same_as<std::expected<void, std::error_code>>;
  {
    b.setReceiveTimeout(us)
  } -> std::same_as<std::expected<void, std::error_code>>;
  { b.recvSome(inbuf) } -> std::same_as<std::expected<size_t, std::error_code>>;
  { b.sendAll(outbuf) } -> std::same_as<std::expected<void, std::error_code>>;
  { b.ensureConnect() } -> std::same_as<std::expected<void, std::error_code>>;
};

template <class F>
class Defer {
 public:
  auto operator=(Defer&&) -> Defer& = delete;
  Defer(const Defer&) = delete;
  auto operator=(const Defer&) -> Defer& = delete;

  Defer(Defer&& o) noexcept(std::is_nothrow_move_constructible_v<F>)
      : f_(std::move(o.f_)), active(o.active) {
    o.active = false;
  }
  explicit Defer(F&& f) : f_(std::forward<F>(f)) {}  // NOLINT

  ~Defer() noexcept {
    if (active) std::invoke(f_);
  }

 private:
  F f_;
  bool active = true;
};

template <class F>
Defer(F) -> Defer<std::decay_t<F>>;

template <TcpBackend Backend>
class SpwRmapTCPNodeImpl : public SpwRmapNodeBase {
 private:
  std::unique_ptr<Backend> tcp_backend_ = nullptr;

  std::vector<uint8_t> recv_buf_ = {};
  std::vector<uint8_t> send_buf_ = {};

  TransactionDatabase transaction_id_database_;

  PacketParser packet_parser_ = {};
  ReadPacketBuilder read_packet_builder_ = {};
  WritePacketBuilder write_packet_builder_ = {};
  uint8_t initiator_logical_address_ = 0xFE;
  BufferPolicy buffer_policy_ = BufferPolicy::AutoResize;
  std::chrono::microseconds send_timeout_{std::chrono::milliseconds{500}};

  std::atomic<bool> running_{false};

  std::function<void(Packet)> on_write_callback_ = nullptr;
  std::function<std::vector<uint8_t>(Packet)> on_read_callback_ = nullptr;

  std::atomic<bool> auto_polling_mode_{false};

  std::mutex send_mtx_;

 public:
  explicit SpwRmapTCPNodeImpl(SpwRmapTCPNodeConfig config) noexcept
      : tcp_backend_(std::make_unique<Backend>(std::move(config.ip_address),
                                               std::move(config.port))),
        recv_buf_(config.recv_buffer_size),
        send_buf_(config.send_buffer_size),
        transaction_id_database_(config.transaction_id_min,
                                 config.transaction_id_max),
        buffer_policy_(config.buffer_policy),
        send_timeout_(config.send_timeout) {}

 public:
  auto setInitiatorLogicalAddress(uint8_t address) -> void {
    initiator_logical_address_ = address;
  }

 protected:
  auto getBackend_() noexcept -> std::unique_ptr<Backend>& {
    return tcp_backend_;
  }

  auto getIpAddress_() const noexcept -> const std::string& {
    return tcp_backend_->getIpAddress();
  }

  auto setIpAddress_(std::string ip_address) noexcept -> void {
    tcp_backend_->setIpAddress(std::move(ip_address));
  }

  auto getPort_() const noexcept -> const std::string& {
    return tcp_backend_->getPort();
  }

  auto setPort_(std::string port) noexcept -> void {
    tcp_backend_->setPort(std::move(port));
  }

  auto getSendTimeout_() const noexcept -> std::chrono::microseconds {
    return send_timeout_;
  }

  auto setSendTimeoutInternal_(std::chrono::microseconds timeout) noexcept
      -> std::expected<void, std::error_code> {
    if (timeout < std::chrono::microseconds::zero()) {
      return std::unexpected{std::make_error_code(std::errc::invalid_argument)};
    }
    send_timeout_ = timeout;
    if (tcp_backend_) {
      auto res = tcp_backend_->setSendTimeout(timeout);
      if (!res.has_value()) {
        return std::unexpected{res.error()};
      }
    }
    return {};
  }

  auto ensureConnectionReady_() noexcept
      -> std::expected<void, std::error_code> {
    if (!tcp_backend_) {
      return std::unexpected{std::make_error_code(std::errc::not_connected)};
    }
    auto ensure_res = tcp_backend_->ensureConnect();
    if (!ensure_res.has_value()) {
      return std::unexpected{ensure_res.error()};
    }
    auto timeout_res = tcp_backend_->setSendTimeout(send_timeout_);
    if (!timeout_res.has_value()) {
      return std::unexpected{timeout_res.error()};
    }
    return {};
  }

  auto connectLoopUntilHealthy_() noexcept
      -> std::expected<void, std::error_code> {
    std::error_code last_error = std::make_error_code(std::errc::not_connected);
    constexpr int kMaxAttempts = 3;
    for (int attempt = 0; attempt < kMaxAttempts && running_.load();
         ++attempt) {
      auto res = ensureConnectionReady_();
      if (res.has_value()) {
        return res;
      }
      last_error = res.error();
      std::this_thread::sleep_for(std::chrono::milliseconds{100});
    }
    return std::unexpected{last_error};
  }

 private:
  auto recvExact_(std::span<uint8_t> buffer)
      -> std::expected<std::size_t, std::error_code> {
    if (!tcp_backend_) {
      spw_rmap::debug::debug(" Not connected");
      return std::unexpected{std::make_error_code(std::errc::not_connected)};
    }
    size_t total_length = buffer.size();
    while (!buffer.empty()) {
      auto res = tcp_backend_->recvSome(buffer);
      if (!res.has_value()) {
        return std::unexpected(res.error());
      }
      if (res.value() == 0) {
        return 0;
      }
      buffer = buffer.subspan(res.value());
    }
    return total_length;
  }

  static inline auto calculateDataLength(
      const std::span<const uint8_t> header) noexcept
      -> std::expected<size_t, std::error_code> {
    if (header.size() < 12) {
      spw_rmap::debug::debug("Header size less than 12 bytes");
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

  auto startWriteAsyncOperation_(
      std::shared_ptr<TargetNodeBase> target_node, uint32_t memory_address,
      const std::span<const uint8_t> data,
      std::function<void(Packet)> on_complete) noexcept -> AsyncOperation {
    AsyncOperation op{};
    auto promise = std::make_shared<PromiseType>();
    op.future = promise->get_future();

    auto transaction_callbacks = TransactionDatabase::CallbackPair{
        .reply = [this, on_complete = std::move(on_complete),
                  promise](const Packet& packet) mutable noexcept -> void {
          try {
            on_complete(packet);
          } catch (const std::exception& e) {
            spw_rmap::debug::debug("Exception in writeAsync callback: ",
                                   e.what());
            promise->set_value(std::unexpected{
                std::make_error_code(std::errc::operation_canceled)});
            return;
          } catch (...) {
            spw_rmap::debug::debug("Unknown exception in writeAsync callback");
            promise->set_value(std::unexpected{
                std::make_error_code(std::errc::operation_canceled)});
            return;
          }
          promise->set_value({});
        },
        .error = [promise](std::error_code ec) mutable noexcept -> void {
          promise->set_value(std::unexpected{ec});
        },
    };
    auto transaction_id_res =
        transaction_id_database_.acquire(std::move(transaction_callbacks));
    if (!transaction_id_res.has_value()) {
      spw_rmap::debug::debug(
          "Failed to get available Transaction ID for writeAsync");
      promise->set_value(std::unexpected{transaction_id_res.error()});
      return op;
    }
    op.transaction_id = transaction_id_res.value();
    const auto transaction_id = *op.transaction_id;

    auto res = sendWritePacket_(std::move(target_node), transaction_id,
                                memory_address, data);
    if (!res.has_value()) {
      promise->set_value(std::unexpected{res.error()});
      transaction_id_database_.release(transaction_id);
      op.transaction_id.reset();
    }
    return op;
  }

  auto startReadAsyncOperation_(
      std::shared_ptr<TargetNodeBase> target_node, uint32_t memory_address,
      uint32_t data_length, std::function<void(Packet)> on_complete) noexcept
      -> AsyncOperation {
    AsyncOperation op{};
    auto promise = std::make_shared<PromiseType>();
    op.future = promise->get_future();

    auto read_callbacks = TransactionDatabase::CallbackPair{
        .reply = [this, on_complete = std::move(on_complete),
                  promise](const Packet& packet) mutable noexcept -> void {
          try {
            on_complete(packet);
          } catch (const std::exception& e) {
            spw_rmap::debug::debug("Exception in readAsync callback: ",
                                   e.what());
            promise->set_value(std::unexpected{
                std::make_error_code(std::errc::operation_canceled)});
            return;
          } catch (...) {
            spw_rmap::debug::debug("Unknown exception in readAsync callback");
            promise->set_value(std::unexpected{
                std::make_error_code(std::errc::operation_canceled)});
            return;
          }
          promise->set_value({});
        },
        .error = [promise](std::error_code ec) mutable noexcept -> void {
          promise->set_value(std::unexpected{ec});
        },
    };
    auto transaction_id_res =
        transaction_id_database_.acquire(std::move(read_callbacks));
    if (!transaction_id_res.has_value()) {
      promise->set_value(std::unexpected{transaction_id_res.error()});
      return op;
    }
    op.transaction_id = transaction_id_res.value();
    const auto transaction_id = *op.transaction_id;

    auto res = sendReadPacket_(std::move(target_node), transaction_id,
                               memory_address, data_length);
    if (!res.has_value()) {
      promise->set_value(std::unexpected{res.error()});
      transaction_id_database_.release(transaction_id);
      op.transaction_id.reset();
    }
    return op;
  }

  auto recvAndParseOnePacket_() -> std::expected<std::size_t, std::error_code> {
    if (!tcp_backend_) {
      spw_rmap::debug::debug("Not connected");
      return std::unexpected{std::make_error_code(std::errc::not_connected)};
    }
    size_t total_size = 0;
    auto eof = false;
    auto recv_buffer = std::span(recv_buf_);
    while (!eof) {
      std::array<uint8_t, 12> header{};
      auto res = recvExact_(header);
      if (!res.has_value()) {
        return std::unexpected(res.error());
      }
      if (res.value() == 0) {
        return 0;
      }
      if (header.at(0) != 0x00 && header.at(0) != 0x01 &&
          header.at(0) != 0x02 && header.at(0) != 0x31 &&
          header.at(0) != 0x30) {
        spw_rmap::debug::debug("Received packet with invalid type byte: ",
                               static_cast<int>(header.at(0)));
        return std::unexpected{std::make_error_code(std::errc::bad_message)};
      }
      if (header.at(1) != 0x00) {
        spw_rmap::debug::debug("Received packet with invalid reserved byte: ",
                               static_cast<int>(header.at(1)));
        return std::unexpected{std::make_error_code(std::errc::bad_message)};
      }

      auto dataLength = calculateDataLength(header);
      if (!dataLength.has_value()) {
        spw_rmap::debug::debug("Failed to calculate data length from header");
        return std::unexpected(dataLength.error());
      }
      if (*dataLength == 0) {
        spw_rmap::debug::debug("Received packet with zero data length");
        return std::unexpected{std::make_error_code(std::errc::bad_message)};
      }
      if (*dataLength > recv_buffer.size()) {
        if (buffer_policy_ == BufferPolicy::Fixed) {
          spw_rmap::debug::debug(
              "Receive buffer too small for incoming packet data");
          return std::unexpected{
              std::make_error_code(std::errc::no_buffer_space)};
        } else {
          recv_buf_.resize(total_size + *dataLength);
          recv_buffer = std::span(recv_buf_).subspan(total_size);
        }
      }
      switch (header.at(0)) {
        case 0x00: {
          auto res = recvExact_(recv_buffer.first(*dataLength));
          if (!res.has_value()) {
            spw_rmap::debug::debug(
                "Failed to receive packet data of type 0x00");
            return std::unexpected(res.error());
          }
          total_size += *res;
          eof = true;
        } break;
        case 0x01: {
          auto res = ignoreNBytes_(*dataLength);
          if (!res.has_value()) {
            spw_rmap::debug::debug("Failed to ignore packet data of type 0x01");
            return std::unexpected(res.error());
          }
          return recvAndParseOnePacket_();
        } break;
        case 0x02: {
          auto res = recvExact_(recv_buffer.first(*dataLength));
          if (!res.has_value()) {
            spw_rmap::debug::debug(
                "Failed to receive packet data of type 0x02");
            return std::unexpected(res.error());
          }
          total_size += *res;
          recv_buffer = recv_buffer.subspan(*dataLength);
        } break;
        case 0x30:
        case 0x31: {
          // Timecode packet
          if (header.at(2) != 0x00 || header.at(3) != 0x00 ||
              header.at(4) != 0x00 || header.at(5) != 0x00 ||
              header.at(6) != 0x00 || header.at(7) != 0x00 ||
              header.at(8) != 0x00 || header.at(9) != 0x00 ||
              header.at(10) != 0x00 || header.at(11) != 0x02) {
            spw_rmap::debug::debug("Received invalid Timecode packet header");
            return std::unexpected{
                std::make_error_code(std::errc::bad_message)};
          }
          std::array<uint8_t, 2> tc{};
          auto res = recvExact_(tc);
          if (!res.has_value()) {
            spw_rmap::debug::debug("Failed to receive Timecode packet data");
            return std::unexpected(res.error());
          }
          if (tc.at(1) != 0x00) {
            spw_rmap::debug::debug("Received invalid Timecode packet data");
            return std::unexpected{
                std::make_error_code(std::errc::bad_message)};
          }
        } break;
        default:
          spw_rmap::debug::debug("Received packet with unknown type byte: ",
                                 static_cast<int>(header.at(0)));
          return std::unexpected{std::make_error_code(std::errc::bad_message)};
      }
    }
    auto status = packet_parser_.parse(std::span(recv_buf_).first(total_size));
    if (status != PacketParser::Status::Success) {
      spw_rmap::debug::debug("Failed to parse received packet");
      return std::unexpected{make_error_code(status)};
    }
    return total_size;
  }

  auto ignoreNBytes_(std::size_t n)
      -> std::expected<std::size_t, std::error_code> {
    if (!tcp_backend_) {
      spw_rmap::debug::debug("Not connected");
      return std::unexpected{std::make_error_code(std::errc::not_connected)};
    }
    const size_t requested_size = n;
    std::array<uint8_t, 16> ignore_buffer{};
    while (n > ignore_buffer.size()) {
      auto res = tcp_backend_->recvSome(ignore_buffer);
      if (!res.has_value()) {
        spw_rmap::debug::debug("Failed to receive data to ignore");
        return std::unexpected{res.error()};
      }
      if (res.value() == 0) {
        spw_rmap::debug::debug("Connection closed while ignoring data");
        return std::unexpected{
            std::make_error_code(std::errc::connection_aborted)};
      }
      n -= res.value();
    }
    if (n > 0) {
      auto res = recvExact_(std::span(ignore_buffer).first(n));
      if (!res.has_value()) {
        spw_rmap::debug::debug("Failed to receive data to ignore");
        return std::unexpected{res.error()};
      }
    }
    return requested_size;
  }

  auto send_(size_t total_size) -> std::expected<void, std::error_code> {
    auto send_buffer = std::span(send_buf_);
    send_buffer[0] = 0x00;
    send_buffer[1] = 0x00;
    send_buffer[2] = 0x00;
    send_buffer[3] = 0x00;
    send_buffer[4] = static_cast<uint8_t>((total_size >> 56) & 0xFF);
    send_buffer[5] = static_cast<uint8_t>((total_size >> 48) & 0xFF);
    send_buffer[6] = static_cast<uint8_t>((total_size >> 40) & 0xFF);
    send_buffer[7] = static_cast<uint8_t>((total_size >> 32) & 0xFF);
    send_buffer[8] = static_cast<uint8_t>((total_size >> 24) & 0xFF);
    send_buffer[9] = static_cast<uint8_t>((total_size >> 16) & 0xFF);
    send_buffer[10] = static_cast<uint8_t>((total_size >> 8) & 0xFF);
    send_buffer[11] = static_cast<uint8_t>((total_size >> 0) & 0xFF);
    return tcp_backend_->sendAll(std::span(send_buf_).first(total_size + 12));
  }

  auto sendReadPacket_(std::shared_ptr<TargetNodeBase> target_node,
                       uint16_t transaction_id, uint32_t memory_address,
                       uint32_t data_length) noexcept
      -> std::expected<void, std::error_code> {
    std::lock_guard<std::mutex> lock(send_mtx_);
    if (!tcp_backend_) {
      spw_rmap::debug::debug("Not connected");
      return std::unexpected{std::make_error_code(std::errc::not_connected)};
    }
    auto expected_length = target_node->getTargetSpaceWireAddress().size() +
                           (target_node->getReplyAddress().size() + 3) / 4 * 4 +
                           4 + 12 + 1;
    auto send_buffer = std::span(send_buf_);
    if (expected_length > send_buffer.size()) {
      if (buffer_policy_ == BufferPolicy::Fixed) {
        spw_rmap::debug::debug("Send buffer too small for Read Packet");
        return std::unexpected{
            std::make_error_code(std::errc::no_buffer_space)};
      } else {
        send_buf_.resize(expected_length);
        send_buffer = std::span(send_buf_);
      }
    }

    auto config = ReadPacketConfig{
        .targetSpaceWireAddress = target_node->getTargetSpaceWireAddress(),
        .replyAddress = target_node->getReplyAddress(),
        .targetLogicalAddress = target_node->getTargetLogicalAddress(),
        .initiatorLogicalAddress = initiator_logical_address_,
        .transactionID = transaction_id,
        .extendedAddress = 0x00,
        .address = memory_address,
        .dataLength = data_length,
    };

    auto res = read_packet_builder_.build(config, send_buffer.subspan(12));
    if (!res.has_value()) {
      spw_rmap::debug::debug("Failed to build Read Packet: ",
                             res.error().message());
      return std::unexpected{res.error()};
    }
    if (send_buffer.size() < read_packet_builder_.getTotalSize(config) + 12) {
      if (buffer_policy_ == BufferPolicy::Fixed) {
        spw_rmap::debug::debug("Send buffer too small for Read Packet");
        return std::unexpected{
            std::make_error_code(std::errc::no_buffer_space)};
      } else {
        send_buf_.resize(read_packet_builder_.getTotalSize(config) + 12);
        send_buffer = std::span(send_buf_);
      }
    }
    return send_(read_packet_builder_.getTotalSize(config));
  }

  auto sendWritePacket_(std::shared_ptr<TargetNodeBase> target_node,
                        uint16_t transaction_id, uint32_t memory_address,
                        const std::span<const uint8_t> data) noexcept
      -> std::expected<void, std::error_code> {
    std::lock_guard<std::mutex> lock(send_mtx_);
    if (!tcp_backend_) {
      spw_rmap::debug::debug("Not connected");
      return std::unexpected{std::make_error_code(std::errc::not_connected)};
    }
    auto expected_length = target_node->getTargetSpaceWireAddress().size() +
                           (target_node->getReplyAddress().size() + 3) / 4 * 4 +
                           4 + 12 + 1 + data.size();
    auto send_buffer = std::span(send_buf_);
    if (expected_length + 12 > send_buffer.size()) {
      if (buffer_policy_ == BufferPolicy::Fixed) {
        spw_rmap::debug::debug("Send buffer too small for Write Packet");
        return std::unexpected{
            std::make_error_code(std::errc::no_buffer_space)};
      } else {
        send_buf_.resize(expected_length + 12);
        send_buffer = std::span(send_buf_);
      }
    }

    auto config = WritePacketConfig{
        .targetSpaceWireAddress = target_node->getTargetSpaceWireAddress(),
        .replyAddress = target_node->getReplyAddress(),
        .targetLogicalAddress = target_node->getTargetLogicalAddress(),
        .initiatorLogicalAddress = initiator_logical_address_,
        .transactionID = transaction_id,
        .extendedAddress = 0x00,
        .address = memory_address,
        .verifyMode = isVerifyMode(),
        .data = data,
    };

    auto res = write_packet_builder_.build(config, send_buffer.subspan(12));
    if (!res.has_value()) {
      spw_rmap::debug::debug("Failed to build Write Packet: ",
                             res.error().message());
      return std::unexpected{res.error()};
    }
    return send_(write_packet_builder_.getTotalSize(config));
  }

 public:
  virtual auto shutdown() noexcept -> std::expected<void, std::error_code> = 0;

  virtual auto isShutdowned() noexcept -> bool = 0;

  auto poll() noexcept -> std::expected<bool, std::error_code> override {
    auto res = recvAndParseOnePacket_();
    if (!res.has_value()) {
      if (isShutdowned()) {
        return false;
      }
      spw_rmap::debug::debug("Error in receiving/parsing packet: ",
                             res.error().message());
      return std::unexpected{res.error()};
    }
    if (res.value() == 0) {
      auto res = shutdown();
      if (!res.has_value()) {
        spw_rmap::debug::debug("Error in shutdown after recv returning 0: ",
                               res.error().message());
        return std::unexpected{res.error()};
      }
      return false;
    }

    auto& packet = packet_parser_.getPacket();

    switch (packet.type) {
      case PacketType::ReadReply:
      case PacketType::WriteReply: {
        if (!transaction_id_database_.contains(packet.transactionID)) {
          spw_rmap::debug::debug(
              "Received packet with out-of-range Transaction ID: ",
              packet.transactionID);
          return std::unexpected{std::make_error_code(std::errc::bad_message)};
        }
        const auto handled = transaction_id_database_.invokeReplyCallback(
            packet.transactionID, packet);
        if (!handled) {
          std::cerr << "No callback registered for Transaction ID: "
                    << packet.transactionID << "\n";
        }
        break;
      }
      case PacketType::Read: {
        std::vector<uint8_t> data{};
        if (on_read_callback_) {
          try {
            data = on_read_callback_(packet);
          } catch (const std::exception& e) {
            spw_rmap::debug::debug("Exception in on_read_callback_: ",
                                   e.what());
            return std::unexpected{
                std::make_error_code(std::errc::operation_canceled)};
          }
        }
        if (data.size() != packet.dataLength) {
          std::cerr << "on_read_callback_ returned data with incorrect length: "
                    << data.size() << " (expected " << packet.dataLength
                    << ")\n";
        }
        auto config = ReadReplyPacketConfig{
            .replyAddress = packet.replyAddress,
            .initiatorLogicalAddress = packet.targetLogicalAddress,
            .status = static_cast<uint8_t>(
                PacketStatusCode::CommandExecutedSuccessfully),
            .targetLogicalAddress = packet.initiatorLogicalAddress,
            .transactionID = packet.transactionID,
            .data = data,
            .incrementMode = true,
        };
        ReadReplyPacketBuilder builder;
        std::lock_guard<std::mutex> lock(send_mtx_);
        auto send_buffer = std::span(send_buf_);
        if (builder.getTotalSize(config) + 12 > send_buffer.size()) {
          if (buffer_policy_ == BufferPolicy::Fixed) {
            spw_rmap::debug::debug(
                "Send buffer too small for Read Reply Packet");
            return std::unexpected{
                std::make_error_code(std::errc::no_buffer_space)};
          }
          send_buf_.resize(builder.getTotalSize(config) + 12);
          send_buffer = std::span(send_buf_);
        }
        auto build_res = builder.build(config, send_buffer.subspan(12));
        if (!build_res.has_value()) {
          spw_rmap::debug::debug("Failed to build Read Reply Packet: ",
                                 build_res.error().message());
          return std::unexpected{build_res.error()};
        }
        auto send_res = send_(builder.getTotalSize(config));
        if (!send_res.has_value()) {
          spw_rmap::debug::debug("Failed to send Read Reply Packet: ",
                                 send_res.error().message());
          return std::unexpected{send_res.error()};
        }
        break;
      }
      case PacketType::Write: {
        if (on_write_callback_) {
          try {
            on_write_callback_(packet);
          } catch (const std::exception& e) {
            spw_rmap::debug::debug("Exception in on_write_callback_: ",
                                   e.what());
            return std::unexpected{
                std::make_error_code(std::errc::operation_canceled)};
          }
        }
        auto config = WriteReplyPacketConfig{
            .replyAddress = packet.replyAddress,
            .initiatorLogicalAddress = packet.targetLogicalAddress,
            .status = static_cast<uint8_t>(
                PacketStatusCode::CommandExecutedSuccessfully),
            .targetLogicalAddress = packet.initiatorLogicalAddress,
            .transactionID = packet.transactionID,
            .incrementMode = true,
            .verifyMode = true,
        };
        WriteReplyPacketBuilder builder;
        std::lock_guard<std::mutex> lock(send_mtx_);
        auto send_buffer = std::span(send_buf_);
        if (builder.getTotalSize(config) + 12 > send_buffer.size()) {
          if (buffer_policy_ == BufferPolicy::Fixed) {
            spw_rmap::debug::debug(
                "Send buffer too small for Write Reply Packet");
            return std::unexpected{
                std::make_error_code(std::errc::no_buffer_space)};
          }
          send_buf_.resize(builder.getTotalSize(config) + 12);
          send_buffer = std::span(send_buf_);
        }
        auto build_res = builder.build(config, send_buffer.subspan(12));
        if (!build_res.has_value()) {
          std::cerr << "Failed to build Write Reply Packet: "
                    << build_res.error().message() << "\n";
          return std::unexpected{build_res.error()};
        }
        auto send_res = send_(builder.getTotalSize(config));
        if (!send_res.has_value()) {
          spw_rmap::debug::debug("Failed to send Write Reply Packet: ",
                                 send_res.error().message());
          return std::unexpected{send_res.error()};
        }
        break;
      }
      default:
        break;
    }
    return true;
  }

  auto runLoop() noexcept -> std::expected<void, std::error_code> override {
    running_.store(true);
    while (running_.load()) {
      auto res = poll();
      if (!res.has_value()) {
        spw_rmap::debug::debug("Error in poll(): ", res.error().message());
        auto ensure_res = ensureConnectionReady_();
        if (ensure_res.has_value()) {
          continue;
        }
        auto reconnect_res = connectLoopUntilHealthy_();
        if (!reconnect_res.has_value()) {
          return std::unexpected{reconnect_res.error()};
        }
        continue;
      }
      if (!res.value()) {
        break;
      }
    }
    return {};
  }

  auto registerOnWrite(std::function<void(Packet)> onWrite) noexcept
      -> void override {
    on_write_callback_ = std::move(onWrite);
  }

  auto registerOnRead(
      std::function<std::vector<uint8_t>(Packet)> onRead) noexcept
      -> void override {
    on_read_callback_ = std::move(onRead);
  }

  auto setTimeout(std::chrono::milliseconds timeout) noexcept -> void {
    transaction_id_database_.setTimeout(timeout);
  }

  auto setAutoPollingMode(bool enable) noexcept -> void {
    auto_polling_mode_ = enable;
  }

  auto write(std::shared_ptr<TargetNodeBase> target_node,
             uint32_t memory_address, const std::span<const uint8_t> data,
             std::chrono::milliseconds timeout =
                 std::chrono::milliseconds{100}) noexcept
      -> std::expected<void, std::error_code> override {
    std::error_code last_error = std::make_error_code(std::errc::timed_out);
    if (auto_polling_mode_) {
      int32_t transaction_id_memo = -1;
      return ensureConnectionReady_()
          .and_then([this, &timeout]() -> std::expected<void, std::error_code> {
            return tcp_backend_->setReceiveTimeout(timeout);
          })
          .and_then([this, &target_node, &memory_address,
                     &data]() -> std::expected<uint16_t, std::error_code> {
            return transaction_id_database_.acquire();
          })
          .and_then([this, &target_node, &memory_address, &data,
                     &transaction_id_memo](uint16_t transaction_id)
                        -> std::expected<void, std::error_code> {
            transaction_id_memo = transaction_id;
            return sendWritePacket_(target_node, transaction_id, memory_address,
                                    data);
          })
          .and_then([this, &target_node, &memory_address,
                     &data]() -> std::expected<std::size_t, std::error_code> {
            return recvAndParseOnePacket_();
          })
          .and_then([this, &transaction_id_memo](std::size_t byte_received)
                        -> std::expected<void, std::error_code> {
            transaction_id_database_.release(
                static_cast<uint16_t>(transaction_id_memo));
            if (byte_received == 0) {
              return std::unexpected{
                  std::make_error_code(std::errc::not_connected)};
            } else {
              auto& packet = packet_parser_.getPacket();
              if (packet.transactionID !=
                  static_cast<uint16_t>(transaction_id_memo)) {
                spw_rmap::debug::debug(
                    "Received packet with unexpected Transaction ID: ",
                    packet.transactionID);
                return std::unexpected{
                    std::make_error_code(std::errc::bad_message)};
              }
              if (packet.type == PacketType::WriteReply) {
                return {};
              } else {
                return std::unexpected{
                    std::make_error_code(std::errc::bad_message)};
              }
            }
          })
          .or_else([this, &transaction_id_memo](std::error_code ec)
                       -> std::expected<void, std::error_code> {
            if (transaction_id_memo >= 0) {
              transaction_id_database_.release(
                  static_cast<uint16_t>(transaction_id_memo));
            }
            return std::unexpected{ec};
          });
    } else {
      auto async_op =
          startWriteAsyncOperation_(target_node, memory_address, data,
                                    [](const Packet&) noexcept -> void {});
      if (async_op.future.wait_for(timeout) == std::future_status::ready) {
        auto res = async_op.future.get();
        if (!res.has_value()) {
          return std::unexpected{res.error()};
        }
        return {};
      }
      if (async_op.transaction_id.has_value()) {
        transaction_id_database_.release(*async_op.transaction_id);
      }
      last_error = std::make_error_code(std::errc::timed_out);
    }
    return std::unexpected{last_error};
  }

  auto writeAsync(std::shared_ptr<TargetNodeBase> target_node,
                  uint32_t memory_address, const std::span<const uint8_t> data,
                  std::function<void(Packet)> on_complete) noexcept
      -> std::future<std::expected<void, std::error_code>> override {
    if (auto_polling_mode_) {
      std::promise<std::expected<void, std::error_code>> prom;
      auto fut = prom.get_future();
      prom.set_value(std::unexpected{
          std::make_error_code(std::errc::operation_not_permitted)});
      return fut;
    }
    auto async_op = startWriteAsyncOperation_(
        std::move(target_node), memory_address, data, std::move(on_complete));
    return std::move(async_op.future);
  }

  auto read(std::shared_ptr<TargetNodeBase> target_node,
            uint32_t memory_address, const std::span<uint8_t> data,
            std::chrono::milliseconds timeout =
                std::chrono::milliseconds{100}) noexcept
      -> std::expected<void, std::error_code> override {
    std::error_code last_error = std::make_error_code(std::errc::timed_out);
    if (auto_polling_mode_) {
      int32_t transaction_id_memo = -1;
      return ensureConnectionReady_()
          .and_then([this, &timeout]() -> std::expected<void, std::error_code> {
            return tcp_backend_->setReceiveTimeout(timeout);
          })
          .and_then([this, &target_node, &memory_address,
                     &data]() -> std::expected<uint16_t, std::error_code> {
            return transaction_id_database_.acquire();
          })
          .and_then([this, &target_node, &memory_address, &data,
                     &transaction_id_memo](uint16_t transaction_id)
                        -> std::expected<void, std::error_code> {
            transaction_id_memo = transaction_id;
            return sendReadPacket_(target_node, transaction_id, memory_address,
                                   data.size());
          })
          .and_then([this, &target_node, &memory_address,
                     &data]() -> std::expected<std::size_t, std::error_code> {
            return recvAndParseOnePacket_();
          })
          .and_then(
              [this, &transaction_id_memo, &data](std::size_t byte_received)
                  -> std::expected<void, std::error_code> {
                transaction_id_database_.release(
                    static_cast<uint16_t>(transaction_id_memo));
                if (byte_received == 0) {
                  return std::unexpected{
                      std::make_error_code(std::errc::not_connected)};
                } else {
                  auto& packet = packet_parser_.getPacket();
                  if (packet.transactionID !=
                      static_cast<uint16_t>(transaction_id_memo)) {
                    spw_rmap::debug::debug(
                        "Received packet with unexpected Transaction ID: ",
                        packet.transactionID);
                    return std::unexpected{
                        std::make_error_code(std::errc::bad_message)};
                  }
                  if (packet.type == PacketType::ReadReply) {
                    transaction_id_database_.release(
                        static_cast<uint16_t>(transaction_id_memo));
                    if (packet.dataLength != data.size() ||
                        packet.data.size() != data.size()) {
                      spw_rmap::debug::debug(
                          "Received Read Reply packet with unexpected data "
                          "length: ",
                          packet.dataLength);
                      return std::unexpected{
                          std::make_error_code(std::errc::bad_message)};
                    }
                    std::ranges::copy(packet.data, data.begin());
                    return {};
                  } else {
                    return std::unexpected{
                        std::make_error_code(std::errc::bad_message)};
                  }
                }
              })
          .or_else([this, &transaction_id_memo](std::error_code ec)
                       -> std::expected<void, std::error_code> {
            if (transaction_id_memo >= 0) {
              transaction_id_database_.release(
                  static_cast<uint16_t>(transaction_id_memo));
            }
            return std::unexpected{ec};
          });
    } else {
      auto async_op = startReadAsyncOperation_(
          std::move(target_node), memory_address, data.size(),
          [data](const Packet& packet) noexcept -> void {
            std::copy_n(packet.data.data(), data.size(), data.data());
          });
      if (async_op.future.wait_for(timeout) == std::future_status::ready) {
        auto res = async_op.future.get();
        if (!res.has_value()) {
          return std::unexpected{res.error()};
        }
        return {};
      }
      if (async_op.transaction_id.has_value()) {
        transaction_id_database_.release(*async_op.transaction_id);
      }
      last_error = std::make_error_code(std::errc::timed_out);
    }
    return std::unexpected{last_error};
  }

  auto readAsync(std::shared_ptr<TargetNodeBase> target_node,
                 uint32_t memory_address, uint32_t data_length,
                 std::function<void(Packet)> on_complete) noexcept
      -> std::future<std::expected<void, std::error_code>> override {
    if (auto_polling_mode_) {
      std::promise<std::expected<void, std::error_code>> prom;
      auto fut = prom.get_future();
      prom.set_value(std::unexpected{
          std::make_error_code(std::errc::operation_not_permitted)});
      return fut;
    }
    auto async_op =
        startReadAsyncOperation_(std::move(target_node), memory_address,
                                 data_length, std::move(on_complete));
    return std::move(async_op.future);
  }

  auto emitTimeCode(uint8_t timecode) noexcept
      -> std::expected<void, std::error_code> override {
    std::lock_guard<std::mutex> lock(send_mtx_);
    if (!tcp_backend_) {
      spw_rmap::debug::debug("Not connected");
      return std::unexpected{std::make_error_code(std::errc::not_connected)};
    }
    std::array<uint8_t, 14> packet{};
    packet.at(0) = 0x30;
    packet.at(1) = 0x00;  // reserved
    for (size_t i = 2; i < 11; ++i) {
      packet.at(i) = 0x00;  // reserved
    }
    packet.at(11) = 0x02;  // reserved
    packet.at(12) = timecode;
    packet.at(13) = 0x00;
    return tcp_backend_->sendAll(packet);
  }
};

}  // namespace internal

}  // namespace spw_rmap
