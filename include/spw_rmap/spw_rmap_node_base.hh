// Copyright (c) 2025 Gen
// Licensed under the MIT License. See LICENSE file for details.
#pragma once

#include <chrono>
#include <cstddef>
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

  [[nodiscard]] auto isVerifyMode() const noexcept -> bool {
    return verify_mode_;
  }

  auto acquireTransaction(TransactionDatabase::Callback callback = {}) noexcept
      -> std::expected<uint16_t, std::error_code> {
    return transaction_id_database_.acquire(std::move(callback));
  }

  [[nodiscard]] auto clampTransactionTimeout(
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

  [[nodiscard]] auto getTransactionDatabase() noexcept -> TransactionDatabase& {
    return transaction_id_database_;
  }

 public:
  virtual ~SpwRmapNodeBase() = default;

  SpwRmapNodeBase(const SpwRmapNodeBase&) = delete;
  auto operator=(const SpwRmapNodeBase&) -> SpwRmapNodeBase& = delete;

  SpwRmapNodeBase(SpwRmapNodeBase&&) = delete;
  auto operator=(SpwRmapNodeBase&&) -> SpwRmapNodeBase& = delete;

  virtual auto poll() -> std::expected<void, std::error_code> = 0;

  virtual auto runLoop() -> std::expected<void, std::error_code> = 0;

  virtual auto registerOnWrite(std::function<void(Packet)> onWrite) noexcept
      -> void = 0;

  virtual auto registerOnRead(
      std::function<std::vector<uint8_t>(Packet)> onRead) noexcept -> void = 0;

  virtual auto registerOnTimeCode(
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
  virtual auto write(const TargetNode& target_node, uint32_t memory_address,
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
  virtual auto read(const TargetNode& target_node, uint32_t memory_address,
                    const std::span<uint8_t> data,
                    std::chrono::milliseconds timeout =
                        std::chrono::milliseconds{100}) noexcept
      -> std::expected<void, std::error_code> = 0;

  /**
   * @brief Writes data to a target node asynchronously.
   *
   * This function sends data to a specific memory address of the target node
   * and resolves the returned future when the reply is received.
   *
   * @param logical_address Logical address of the target node.
   * @param memory_address Target memory address.
   * @param data Data to write.
   */
  virtual auto writeAsync(
      const TargetNode& target_node, uint32_t memory_address,
      const std::span<const uint8_t> data,
      std::function<void(std::expected<Packet, std::error_code>)>
          on_complete) noexcept -> std::expected<uint16_t, std::error_code> = 0;

  /**
   * @brief Reads data from a target node asynchronously.
   *
   * This function retrieves data from a specific memory address of the target
   * node and resolves the future once the read reply is received.
   *
   * @param logical_address Logical address of the target node.
   * @param memory_address Target memory address.
   * @param data Reference to a span where the read data will be stored.
   */
  virtual auto readAsync(
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
  virtual auto emitTimeCode(uint8_t timecode) noexcept
      -> std::expected<void, std::error_code> = 0;

  /**
   * @brief Configures the timeout used by the transaction ID database.
   *
   * Every in-flight transaction reserves a Transaction ID; when a reply takes
   * longer than this duration the entry is considered lost and will eventually
   * be recycled. If `read`/`write` are invoked with a timeout that exceeds this
   * limit (non-zero timeout), the request timeout is clamped to the Transaction
   * ID timeout to guarantee consistency. Supplying `0ms` disables automatic
   * reclamation and clamping entirely.
   */
  virtual auto setTransactionTimeout(std::chrono::milliseconds timeout) noexcept
      -> void {
    transaction_id_timeout_ = timeout;
    transaction_id_database_.setTimeout(timeout);
  }

  virtual auto cancelTransaction(uint16_t transaction_id) noexcept -> void {
    transaction_id_database_.release(transaction_id);
  }

  virtual auto setVerifyMode(bool verify_mode) noexcept -> void {
    verify_mode_ = verify_mode;
  }

  [[nodiscard]] virtual auto getInitiatorLogicalAddress() const noexcept
      -> uint8_t {
    return initiator_logical_address_;
  }

  virtual auto setInitiatorLogicalAddress(uint8_t logical_address) noexcept
      -> void {
    initiator_logical_address_ = logical_address;
  }
};

}  // namespace spw_rmap
