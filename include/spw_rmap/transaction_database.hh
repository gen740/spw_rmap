#pragma once

#include <cassert>
#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <mutex>
#include <system_error>
#include <utility>
#include <vector>

#include "spw_rmap/internal/debug.hh"
#include "spw_rmap/packet_parser.hh"

namespace spw_rmap {

class TransactionDatabase {
 public:
  using Callback = std::function<void(std::expected<Packet, std::error_code>)>;

  TransactionDatabase(uint16_t id_min, uint16_t id_max) noexcept
      : id_min_(id_min),
        id_max_(id_max),
        next_id_(id_min),
        entries_(id_max - id_min) {
    assert(id_max_ > id_min_);
    for (std::size_t i = 0; i < entries_.size(); ++i) {
      auto& entry = entries_[i];
      entry.transaction_id = static_cast<uint16_t>(id_min_ + i);
      entry.available = true;
      entry.last_used = std::chrono::steady_clock::time_point::min();
    }
  }

  [[nodiscard]] constexpr auto contains(uint16_t transaction_id) const noexcept
      -> bool {
    return transaction_id >= id_min_ && transaction_id < id_max_;
  }

  auto setTimeout(std::chrono::milliseconds timeout) noexcept -> void {
    timeout_ = timeout;
  }

  auto acquire(Callback callback = Callback{}) noexcept
      -> std::expected<uint16_t, std::error_code> {
    for (size_t i = 0; i < entries_.size(); ++i) {
      Callback timeout_callback = nullptr;
      const auto now = std::chrono::steady_clock::now();
      {
        std::unique_lock<std::mutex> lock(mutex_);
        auto& entry = entries_[next_id_ - id_min_];
        next_id_++;
        if (next_id_ >= id_max_) {
          next_id_ = id_min_;
        }
        const bool has_callback = static_cast<bool>(entry.callback);
        const bool timed_out = has_callback && timeout_.count() > 0 &&
                               (now - entry.last_used > timeout_);
        if (entry.available || timed_out) [[likely]] {
          if (!entry.available && timed_out) {
            spw_rmap::debug::debug(
                "TransactionDatabase::acquire: Reusing timed-out transaction "
                "ID ",
                entry.transaction_id);
            timeout_callback = std::move(entry.callback);
          }
          entry.available = false;
          entry.last_used = now;
          entry.callback = std::move(callback);
          lock.unlock();
          if (timeout_callback) {
            timeout_callback(
                std::unexpected(std::make_error_code(std::errc::timed_out)));
          }
          return entry.transaction_id;
        }
      }
    }
    return std::unexpected{
        std::make_error_code(std::errc::resource_unavailable_try_again)};
  }

  auto invokeReplyCallback(uint16_t transaction_id,
                           const Packet& packet) noexcept -> bool {
    Callback callback = nullptr;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      auto* entry = getEntry_(transaction_id);
      if (entry == nullptr || !entry->callback) {
        return false;
      }
      callback = std::move(entry->callback);
      entry->clear();
    }
    callback(packet);
    return true;
  }

  auto release(uint16_t transaction_id) noexcept -> void {
    std::lock_guard<std::mutex> lock(mutex_);
    auto* entry = getEntry_(transaction_id);
    if (entry != nullptr) [[likely]] {
      return entry->clear();
    }
    spw_rmap::debug::debug(
        "TransactionDatabase::release: Invalid transaction ID ",
        transaction_id);
  }

 private:
  struct Entry {
    bool available = true;
    std::chrono::steady_clock::time_point last_used =
        std::chrono::steady_clock::time_point::min();
    uint16_t transaction_id = 0;
    Callback callback = nullptr;
    auto clear() noexcept -> void {
      available = true;
      last_used = std::chrono::steady_clock::time_point::min();
      callback = nullptr;
    }
  };

  auto getEntry_(uint16_t transaction_id) noexcept -> Entry* {
    if (!contains(transaction_id)) [[unlikely]] {
      return nullptr;
    }
    return &entries_[transaction_id - id_min_];
  }

  uint16_t id_min_;
  uint16_t id_max_;
  uint16_t next_id_;
  std::chrono::milliseconds timeout_{std::chrono::seconds(1)};
  std::vector<Entry> entries_;
  std::mutex mutex_;
};

}  // namespace spw_rmap
