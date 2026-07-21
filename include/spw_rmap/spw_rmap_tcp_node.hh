// Copyright (c) 2025 Gen
// Licensed under the MIT License. See LICENSE file for details.
#pragma once

#include <chrono>
#include <cstring>
#include <expected>
#include <mutex>

#include "spw_rmap/internal/spw_rmap_tcp_node_impl.hh"
#include "spw_rmap/internal/tcp_client.hh"
#include "spw_rmap/internal/tcp_server.hh"

namespace spw_rmap {

using namespace std::chrono_literals;

class SpwRmapTCPClient
    : public internal::SpwRmapTCPNodeImpl<internal::TCPClient> {
 private:
  std::mutex shutdown_mtx_;
  bool shutdowned_ = false;

 public:
  using SpwRmapTCPNodeImpl::SpwRmapTCPNodeImpl;

  auto Connect(std::chrono::microseconds connect_timeout = 100ms)
      -> std::expected<void, std::error_code> {
    std::lock_guard<std::mutex> lock(shutdown_mtx_);
    if (!GetBackend()) [[unlikely]] {
      return std::unexpected{std::make_error_code(std::errc::not_connected)};
    }
    auto res = GetBackend()->Connect(connect_timeout);
    shutdowned_ = false;
    if (!res.has_value()) [[unlikely]] {
      GetBackend()->Disconnect();
      return std::unexpected{res.error()};
    }
    auto timeout_res = GetBackend()->SetSendTimeout(GetSendTimeout());
    if (!timeout_res.has_value()) [[unlikely]] {
      GetBackend()->Disconnect();
      return std::unexpected{timeout_res.error()};
    }
    return {};
  }

  auto SetSendTimeout(std::chrono::microseconds timeout) noexcept
      -> std::expected<void, std::error_code> {
    std::lock_guard<std::mutex> lock(shutdown_mtx_);
    if (!GetBackend()) [[unlikely]] {
      return std::unexpected{std::make_error_code(std::errc::not_connected)};
    }
    return SetSendTimeoutInternal(timeout);
  }

  auto Stop() noexcept -> std::expected<void, std::error_code> override {
    std::lock_guard<std::mutex> lock(shutdown_mtx_);
    RequestRunLoopStop();
    if (!GetBackend()) [[unlikely]] {
      return {};
    }
    auto result = GetBackend()->Shutdown();
    if (!result.has_value() && result.error() != std::errc::bad_file_descriptor)
        [[unlikely]] {
      return std::unexpected{result.error()};
    }
    return {};
  }

  auto Shutdown() noexcept -> std::expected<void, std::error_code> override {
    std::lock_guard<std::mutex> lock(shutdown_mtx_);
    RequestRunLoopStop();
    if (!GetBackend()) [[unlikely]] {
      shutdowned_ = true;
      return {};
    }
    auto res = GetBackend()->Shutdown();
    shutdowned_ = true;
    if (!res.has_value()) [[unlikely]] {
      return std::unexpected{res.error()};
    }
    GetBackend() = nullptr;
    return {};
  }

  auto IsShutdowned() noexcept -> bool override {
    std::lock_guard<std::mutex> lock(shutdown_mtx_);
    return shutdowned_;
  }
};

class SpwRmapTCPServer
    : public internal::SpwRmapTCPNodeImpl<internal::TCPServer> {
 private:
  std::mutex shutdown_mtx_;
  bool shutdowned_ = false;

 public:
  explicit SpwRmapTCPServer(SpwRmapTCPNodeConfig config) noexcept
      : internal::SpwRmapTCPNodeImpl<internal::TCPServer>(std::move(config)) {}

  auto AcceptOnce() -> std::expected<void, std::error_code> {
    // Accept waits without shutdown_mtx_ so Stop()/Shutdown() can abort it.
    auto res = GetBackend()->AcceptOnce();
    std::lock_guard<std::mutex> lock(shutdown_mtx_);
    if (!res.has_value()) [[unlikely]] {
      std::cerr << "Failed to accept TCP connection: " << res.error().message()
                << "\n";
      return std::unexpected{res.error()};
    }
    auto timeout_res = GetBackend()->SetSendTimeout(GetSendTimeout());
    if (!timeout_res.has_value()) [[unlikely]] {
      std::cerr << "Failed to set send timeout: "
                << timeout_res.error().message() << "\n";
      auto res = GetBackend()->Shutdown();
      if (!res.has_value()) [[unlikely]] {
        return std::unexpected{res.error()};
      }
      return std::unexpected{timeout_res.error()};
    }
    shutdowned_ = false;
    return {};
  }

  auto SetSendTimeout(std::chrono::microseconds timeout) noexcept
      -> std::expected<void, std::error_code> {
    std::lock_guard<std::mutex> lock(shutdown_mtx_);
    return SetSendTimeoutInternal(timeout);
  }

  auto Stop() noexcept -> std::expected<void, std::error_code> override {
    std::lock_guard<std::mutex> lock(shutdown_mtx_);
    RequestRunLoopStop();
    if (!GetBackend()) {
      return {};
    }
    auto result = GetBackend()->Shutdown();
    if (!result.has_value() && result.error() != std::errc::bad_file_descriptor)
        [[unlikely]] {
      return std::unexpected{result.error()};
    }
    return {};
  }

  auto Shutdown() noexcept -> std::expected<void, std::error_code> override {
    std::lock_guard<std::mutex> lock(shutdown_mtx_);
    RequestRunLoopStop();
    if (GetBackend()) {
      auto res = GetBackend()->Shutdown();
      shutdowned_ = true;
      if (!res.has_value()) [[unlikely]] {
        return std::unexpected{res.error()};
      }
    }
    return {};
  }

  auto IsShutdowned() noexcept -> bool override {
    std::lock_guard<std::mutex> lock(shutdown_mtx_);
    return shutdowned_;
  }
};

};  // namespace spw_rmap
