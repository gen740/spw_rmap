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

#include "spw_rmap/packet_parser.hh"

namespace spw_rmap::internal {

class TransactionDatabase {
 public:
  struct CallbackPair {
    std::function<void(const Packet&)> reply{};
    std::function<void(std::error_code)> error{};
  };

  TransactionDatabase(uint16_t id_min, uint16_t id_max) noexcept
      : id_min_(id_min), id_max_(id_max), entries_(id_max - id_min) {
    assert(id_max_ > id_min_);
    for (std::size_t i = 0; i < entries_.size(); ++i) {
      auto& entry = entries_[i];
      entry.transaction_id = static_cast<uint16_t>(id_min_ + i);
      entry.available = true;
      entry.last_used = std::chrono::steady_clock::time_point::min();
    }
  }

  [[nodiscard]] auto contains(uint16_t transaction_id) const noexcept -> bool {
    return transaction_id >= id_min_ && transaction_id < id_max_;
  }

  auto setTimeout(std::chrono::milliseconds timeout) noexcept -> void {
    timeout_ = timeout;
  }

  auto acquire() noexcept -> std::expected<uint16_t, std::error_code> {
    return acquire(CallbackPair{});
  }

  auto acquire(CallbackPair callbacks) noexcept
      -> std::expected<uint16_t, std::error_code> {
    while (true) {
      std::function<void(std::error_code)> expired_error_callback = nullptr;
      {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto now = std::chrono::steady_clock::now();
        Entry* expired_entry = nullptr;
        for (auto& entry : entries_) {
          if (entry.available) {
            entry.available = false;
            entry.last_used = now;
            entry.reply_callback = std::move(callbacks.reply);
            entry.error_callback = std::move(callbacks.error);
            return entry.transaction_id;
          }
          if (expired_entry == nullptr && !entry.available) {
            if (now - entry.last_used > timeout_) {
              expired_entry = &entry;
            }
          }
        }
        if (expired_entry == nullptr) {
          return std::unexpected{
              std::make_error_code(std::errc::resource_unavailable_try_again)};
        }
        expired_error_callback = std::move(expired_entry->error_callback);
        expired_entry->reply_callback = nullptr;
        expired_entry->error_callback = nullptr;
        expired_entry->available = true;
        expired_entry->last_used = std::chrono::steady_clock::time_point::min();
      }
      if (expired_error_callback) {
        expired_error_callback(std::make_error_code(std::errc::timed_out));
      }
    }
  }

  auto invokeReplyCallback(uint16_t transaction_id,
                           const Packet& packet) noexcept -> bool {
    std::function<void(const Packet&)> callback = nullptr;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      auto* entry = getEntry_(transaction_id);
      if (entry == nullptr || !entry->reply_callback) {
        return false;
      }
      callback = std::move(entry->reply_callback);
      entry->reply_callback = nullptr;
      entry->error_callback = nullptr;
      entry->available = true;
      entry->last_used = std::chrono::steady_clock::time_point::min();
    }
    callback(packet);
    return true;
  }

  auto invokeErrorCallback(uint16_t transaction_id,
                           std::error_code error) noexcept -> bool {
    std::function<void(std::error_code)> callback = nullptr;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      auto* entry = getEntry_(transaction_id);
      if (entry == nullptr || !entry->error_callback) {
        if (entry != nullptr) {
          entry->reply_callback = nullptr;
        }
        return false;
      }
      callback = std::move(entry->error_callback);
      entry->reply_callback = nullptr;
      entry->error_callback = nullptr;
      entry->available = true;
      entry->last_used = std::chrono::steady_clock::time_point::min();
    }
    callback(error);
    return true;
  }

  auto release(uint16_t transaction_id) noexcept -> void {
    std::lock_guard<std::mutex> lock(mutex_);
    auto* entry = getEntry_(transaction_id);
    if (entry == nullptr) {
      assert(false && "Transaction ID out of range");
      return;
    }
    entry->reply_callback = nullptr;
    entry->error_callback = nullptr;
    entry->available = true;
    entry->last_used = std::chrono::steady_clock::time_point::min();
  }

 private:
  struct Entry {
    bool available = true;
    std::chrono::steady_clock::time_point last_used =
        std::chrono::steady_clock::time_point::min();
    uint16_t transaction_id = 0;
    std::function<void(const Packet&)> reply_callback = nullptr;
    std::function<void(std::error_code)> error_callback = nullptr;
  };

  auto getEntry_(uint16_t transaction_id) noexcept -> Entry* {
    if (!contains(transaction_id)) {
      return nullptr;
    }
    return &entries_[transaction_id - id_min_];
  }

  uint16_t id_min_;
  uint16_t id_max_;
  std::chrono::milliseconds timeout_{std::chrono::seconds(1)};
  std::vector<Entry> entries_;
  std::mutex mutex_;
};

}  // namespace spw_rmap::internal
