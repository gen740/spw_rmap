// Copyright (c) 2025 Gen
// Licensed under the MIT License. See LICENSE file for details.
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>

namespace spw_rmap::internal {

/**
 * @class TCPServer
 * @brief A class for managing a TCP server.
 *
 * This TCPServer is supposed to be used for RMAP communication over TCP.
 * This server accepts a single connection at a time.
 */
class TCPServer {
 private:
  int listen_fd_ = -1;  // listening socket
  int client_fd_ = -1;  // accepted client socket

  static auto CloseRetry(int fd) noexcept -> void;
  std::string bind_address_;
  std::string port_;
  std::optional<std::chrono::microseconds> last_send_timeout_{};
  std::optional<std::chrono::microseconds> last_receive_timeout_{};

 public:
  TCPServer() = delete;
  TCPServer(const TCPServer&) = delete;
  auto operator=(const TCPServer&) -> TCPServer& = delete;
  TCPServer(TCPServer&&) = delete;
  auto operator=(TCPServer&&) -> TCPServer& = delete;

  TCPServer(std::string bind_address, std::string port) noexcept
      : bind_address_(std::move(bind_address)), port_(std::move(port)) {};

  ~TCPServer() noexcept;

  [[nodiscard]] auto AcceptOnce() noexcept
      -> std::expected<void, std::error_code>;

  [[nodiscard]] auto EnsureConnect() noexcept
      -> std::expected<void, std::error_code>;

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
    return bind_address_;
  }

  auto SetIpAddress(std::string ip_address) noexcept -> void {
    bind_address_ = std::move(ip_address);
  }

  [[nodiscard]] auto GetPort() const noexcept -> const std::string& {
    return port_;
  }

  auto SetPort(std::string port) noexcept -> void { port_ = std::move(port); }

 private:
  auto ResetTimeoutCache() noexcept -> void;
};

}  // namespace spw_rmap::internal
