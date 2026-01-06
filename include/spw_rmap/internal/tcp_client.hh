// Copyright (c) 2025 Gen
// Licensed under the MIT License. See LICENSE file for details.
#pragma once

#include <chrono>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <system_error>
#include <utility>

namespace spw_rmap::internal {

using namespace std::chrono_literals;

/**
 * @class TCPClient
 * @brief A class for managing TCP connections.
 *
 * This TCPClient are supposed to be used for RMAP communication over TCP.
 */
class TCPClient {
 private:
  int fd_ = -1;

  std::string ip_address_;
  std::string port_;
  std::optional<std::chrono::microseconds> last_send_timeout_{};
  std::optional<std::chrono::microseconds> last_receive_timeout_{};

  auto ResetTimeoutCache() noexcept -> void;

 public:
  TCPClient() = delete;
  TCPClient(const TCPClient&) = delete;
  auto operator=(const TCPClient&) -> TCPClient& = delete;
  TCPClient(TCPClient&&) = delete;
  auto operator=(TCPClient&&) -> TCPClient& = delete;

  TCPClient(std::string ip_address, std::string port)
      : ip_address_(std::move(ip_address)), port_(std::move(port)) {}

  ~TCPClient();

  [[nodiscard]] auto Connect(std::chrono::microseconds timeout = 500ms) noexcept
      -> std::expected<void, std::error_code>;

  [[nodiscard]] auto EnsureConnect(
      std::chrono::microseconds timeout = 500ms) noexcept
      -> std::expected<void, std::error_code>;

  auto Disconnect() noexcept -> void;

  [[nodiscard]] auto SetSendTimeout(std::chrono::microseconds timeout) noexcept
      -> std::expected<void, std::error_code>;

  [[nodiscard]] auto SetReceiveTimeout(
      std::chrono::microseconds timeout) noexcept
      -> std::expected<void, std::error_code>;

  [[nodiscard]] auto SendAll(std::span<const uint8_t> data) noexcept
      -> std::expected<void, std::error_code>;

  [[nodiscard]] auto RecvSome(std::span<uint8_t> buf) noexcept
      -> std::expected<size_t, std::error_code>;

  [[nodiscard]] auto Shutdown() noexcept
      -> std::expected<void, std::error_code>;

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
};

}  // namespace spw_rmap::internal
