// Copyright (c) 2025 Gen
// Licensed under the MIT License. See LICENSE file for details.
#pragma once

#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <span>
#include <system_error>
#include <utility>

#include "spw_rmap/packet_parser.hh"
#include "spw_rmap/target_node.hh"
#include "spw_rmap/transaction_database.hh"

namespace spw_rmap {

class SpwRmapNodeBase {
  bool verify_mode_{true};
  TransactionDatabase transaction_id_database_;
  std::chrono::milliseconds transaction_id_timeout_{std::chrono::seconds(1)};
  uint8_t initiator_logical_address_{0xFE};

 protected:
  explicit SpwRmapNodeBase(uint16_t transaction_id_min,
                           uint16_t transaction_id_max) noexcept
      : transaction_id_database_(transaction_id_min, transaction_id_max) {}

  SpwRmapNodeBase() : SpwRmapNodeBase(0x0000, 0x00FF) {}

  [[nodiscard]] auto IsVerifyMode() const noexcept -> bool {
    return verify_mode_;
  }

  auto AcquireTransaction(TransactionDatabase::Callback callback = {}) noexcept
      -> std::expected<uint16_t, std::error_code> {
    return transaction_id_database_.Acquire(std::move(callback));
  }

  [[nodiscard]] auto ClampTransactionTimeout(
      std::chrono::milliseconds requested) const noexcept
      -> std::chrono::milliseconds {
    if (transaction_id_timeout_.count() == 0) {
      return requested;
    }
    if (requested.count() == 0 || requested > transaction_id_timeout_) {
      return transaction_id_timeout_;
    }
    return requested;
  }

  [[nodiscard]] auto GetTransactionDatabase() noexcept -> TransactionDatabase& {
    return transaction_id_database_;
  }

 public:
  virtual ~SpwRmapNodeBase() = default;

  SpwRmapNodeBase(const SpwRmapNodeBase&) = delete;
  auto operator=(const SpwRmapNodeBase&) -> SpwRmapNodeBase& = delete;

  SpwRmapNodeBase(SpwRmapNodeBase&&) = delete;
  auto operator=(SpwRmapNodeBase&&) -> SpwRmapNodeBase& = delete;

  virtual auto Poll() -> std::expected<void, std::error_code> = 0;

  virtual auto RunLoop() -> std::expected<void, std::error_code> = 0;

  /**
   * @brief Requests a running receive loop to stop.
   *
   * This interrupts a blocking receive but keeps the node object alive.  Join
   * the thread executing RunLoop() before calling Shutdown().
   */
  virtual auto Stop() noexcept -> std::expected<void, std::error_code> = 0;

  /**
   * @brief Registers the callback invoked for an incoming write command.
   *
   * The callback must not throw. It is invoked from a `noexcept` context, so
   * throwing an exception results in `std::terminate`.
   */
  virtual auto RegisterOnWrite(std::function<void(Packet)> on_write) noexcept
      -> void = 0;

  /**
   * @brief Registers the callback invoked for an incoming read command.
   *
   * The callback must not throw. It is invoked from a `noexcept` context, so
   * throwing an exception results in `std::terminate`.
   */
  virtual auto RegisterOnRead(
      std::function<std::vector<uint8_t>(Packet)> on_read) noexcept -> void = 0;

  /**
   * @brief Registers the callback invoked for an incoming time code.
   *
   * The callback must not throw. It is invoked from a `noexcept` context, so
   * throwing an exception results in `std::terminate`.
   */
  virtual auto RegisterOnTimeCode(
      std::function<void(uint8_t)> /* onTimeCode */) noexcept -> void {}

  /**
   * @brief Writes data to a target node.
   *
   * This function sends data to a specific memory address of the target node.
   * The write operation is performed synchronously.
   *
   * @param logical_address Logical address of the target node.
   * @param memory_address Target memory address.
   * @param data Data to write.
   */
  virtual auto Write(const TargetNode& target_node, uint32_t memory_address,
                     const std::span<const uint8_t> data,
                     std::chrono::milliseconds timeout =
                         std::chrono::milliseconds{100}) noexcept
      -> std::expected<void, std::error_code> = 0;

  /**
   * @brief Reads data from a target node.
   *
   * This function retrieves data from a specific memory address of the target
   * node. The read operation is performed synchronously.
   *
   * @param logical_address Logical address of the target node.
   * @param memory_address Target memory address.
   * @param data Reference to a span where the read data will be stored.
   */
  virtual auto Read(const TargetNode& target_node, uint32_t memory_address,
                    const std::span<uint8_t> data,
                    std::chrono::milliseconds timeout =
                        std::chrono::milliseconds{100}) noexcept
      -> std::expected<void, std::error_code> = 0;

  /**
   * @brief Writes data to a target node asynchronously.
   *
   * This function builds and sends the command before returning its reserved
   * transaction ID. Poll() or RunLoop() invokes the callback when the matching
   * reply is received; with a concurrent receive loop this can happen before
   * WriteAsync() returns.
   *
   * This call does not start a deadline timer. An unanswered transaction stays
   * pending until it is cancelled or a later transaction allocation reclaims
   * its ID after the timeout configured by SetTransactionTimeout(). Therefore,
   * if no later transaction is allocated, its callback can remain pending even
   * after that timeout has elapsed.
   *
   * @param logical_address Logical address of the target node.
   * @param memory_address Target memory address.
   * @param data Data to write.
   * @param on_complete Completion callback. It must not throw; throwing from
   *                    it results in `std::terminate`.
   */
  virtual auto WriteAsync(
      const TargetNode& target_node, uint32_t memory_address,
      const std::span<const uint8_t> data,
      std::function<void(std::expected<Packet, std::error_code>)>
          on_complete) noexcept -> std::expected<uint16_t, std::error_code> = 0;

  /**
   * @brief Reads data from a target node asynchronously.
   *
   * This function builds and sends the command before returning its reserved
   * transaction ID. Poll() or RunLoop() invokes the callback with the parsed
   * reply; with a concurrent receive loop this can happen before ReadAsync()
   * returns.
   *
   * This call does not start a deadline timer. An unanswered transaction stays
   * pending until it is cancelled or a later transaction allocation reclaims
   * its ID after the timeout configured by SetTransactionTimeout(). Therefore,
   * if no later transaction is allocated, its callback can remain pending even
   * after that timeout has elapsed.
   *
   * @param logical_address Logical address of the target node.
   * @param memory_address Target memory address.
   * @param data_length Number of bytes requested from the target.
   * @param on_complete Completion callback. It must not throw; throwing from
   *                    it results in `std::terminate`.
   */
  virtual auto ReadAsync(
      const TargetNode& target_node, uint32_t memory_address,
      uint32_t data_length,
      std::function<void(std::expected<Packet, std::error_code>)>
          on_complete) noexcept -> std::expected<uint16_t, std::error_code> = 0;

  /**
   * @brief Emits a time code.
   *
   * Sends a 6-bit time code. The upper 2 bits are ignored.
   *
   * @param timecode Time code to emit.
   */
  virtual auto EmitTimeCode(uint8_t timecode) noexcept
      -> std::expected<void, std::error_code> = 0;

  /**
   * @brief Configures the timeout used by the transaction ID database.
   *
   * This timeout is a lazy Transaction ID reclamation threshold, not an active
   * deadline timer. Expiration is checked only while allocating a later
   * transaction. When allocation reaches an expired entry, its callback is
   * invoked with `std::errc::timed_out` and the ID is reused. Merely allowing
   * the configured duration to elapse does not invoke the callback; without a
   * later allocation, the transaction remains pending.
   *
   * If `Read`/`Write` are invoked with a timeout that exceeds this non-zero
   * limit, their request timeout is clamped to this value. Supplying `0ms`
   * disables automatic reclamation and clamping entirely. Applications that
   * require prompt asynchronous deadlines must run their own timer, complete
   * their own operation state, and call CancelTransaction() to release the ID.
   */
  virtual auto SetTransactionTimeout(std::chrono::milliseconds timeout) noexcept
      -> void {
    transaction_id_timeout_ = timeout;
    transaction_id_database_.SetTimeout(timeout);
  }

  /**
   * @brief Releases a pending Transaction ID without invoking its callback.
   */
  virtual auto CancelTransaction(uint16_t transaction_id) noexcept -> void {
    transaction_id_database_.Release(transaction_id);
  }

  virtual auto SetVerifyMode(bool verify_mode) noexcept -> void {
    verify_mode_ = verify_mode;
  }

  [[nodiscard]] virtual auto GetInitiatorLogicalAddress() const noexcept
      -> uint8_t {
    return initiator_logical_address_;
  }

  virtual auto SetInitiatorLogicalAddress(uint8_t logical_address) noexcept
      -> void {
    initiator_logical_address_ = logical_address;
  }
};

}  // namespace spw_rmap
