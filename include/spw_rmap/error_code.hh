// Copyright (c) 2025 Gen
// Licensed under the MIT License. See LICENSE file for details.
#pragma once

#include <system_error>

#include "spw_rmap/packet_parser.hh"

namespace spw_rmap {

enum class RMAPParseStatus {
  kHeaderCrcError = 0,
  kDataCrcError = 1,
  kIncompletePacket = 2,
  kInvalidHeader = 3,
  kUnknownProtocolIdentifier = 4,
};

class RMAPStatusCodeCategory final : public std::error_category {
 public:
  [[nodiscard]] auto name() const noexcept -> const char* override {
    return "RMAPStatusCode";
  }

  [[nodiscard]] auto message(int ev) const -> std::string override {
    switch (static_cast<RMAPParseStatus>(ev)) {
      case RMAPParseStatus::kHeaderCrcError:
        return "Header CRC error";
      case RMAPParseStatus::kDataCrcError:
        return "Data CRC error";
      case RMAPParseStatus::kIncompletePacket:
        return "Incomplete packet";
      case RMAPParseStatus::kInvalidHeader:
        return "Invalid RMAP header";
      case RMAPParseStatus::kUnknownProtocolIdentifier:
        return "Unknown protocol identifier";
      default:
        return "Unknown status code";
    }
  }
};

auto status_code_category() noexcept -> const std::error_category&;  // NOLINT

inline auto make_error_code(RMAPParseStatus e) noexcept  // NOLINT
    -> std::error_code {
  return {static_cast<int>(e), status_code_category()};
}

class RMAPReplyStatusCategory final : public std::error_category {
 public:
  [[nodiscard]] auto name() const noexcept -> const char* override {
    return "RMAPReplyStatus";
  }

  [[nodiscard]] auto message(int ev) const -> std::string override {
    switch (static_cast<PacketStatusCode>(ev)) {
      case PacketStatusCode::kCommandExecutedSuccessfully:
        return "Command executed successfully";
      case PacketStatusCode::kGeneralErrorCode:
        return "General RMAP error";
      case PacketStatusCode::kUnusedRmapPacketTypeOrCommandCode:
        return "Unused RMAP packet type or command code";
      case PacketStatusCode::kInvalidKey:
        return "Invalid RMAP key";
      case PacketStatusCode::kInvalidDataCrc:
        return "Invalid RMAP data CRC";
      case PacketStatusCode::kEarlyEop:
        return "Early EOP";
      case PacketStatusCode::kTooMuchData:
        return "Too much data";
      case PacketStatusCode::kEep:
        return "EEP received";
      case PacketStatusCode::kVerifyBufferOverrun:
        return "Verify buffer overrun";
      case PacketStatusCode::kRmapCommandNotImplementedOrNotAuthorised:
        return "RMAP command not implemented or not authorised";
      case PacketStatusCode::kRmwDataLengthError:
        return "RMW data length error";
      case PacketStatusCode::kInvalidTargetLogicalAddress:
        return "Invalid target logical address";
      default:
        return "Unknown RMAP reply status";
    }
  }
};

auto reply_status_category() noexcept -> const std::error_category&;  // NOLINT

inline auto make_error_code(PacketStatusCode e) noexcept  // NOLINT
    -> std::error_code {
  return {static_cast<int>(e), reply_status_category()};
}

}  // namespace spw_rmap

namespace std {

template <>
struct is_error_code_enum<spw_rmap::RMAPParseStatus> : true_type {};

template <>
struct is_error_code_enum<spw_rmap::PacketStatusCode> : true_type {};

}  // namespace std
