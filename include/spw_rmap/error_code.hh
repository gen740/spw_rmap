// Copyright (c) 2025 Gen
// Licensed under the MIT License. See LICENSE file for details.
#pragma once

#include <system_error>

namespace spw_rmap {

enum class ParseStatus {
  Success = 0,
  InvalidPacket = 2,
  HeaderCRCError = 3,
  DataCRCError = 4,
  IncompletePacket = 5,
  NotReplyPacket = 6,
  PacketStatusError = 7,
  UnknownProtocolIdentifier = 8,
};

class StatusCodeCategory final : public std::error_category {
 public:
  [[nodiscard]] auto name() const noexcept -> const char* override {
    return "StatusCode";
  }

  [[nodiscard]] auto message(int ev) const -> std::string override {
    switch (static_cast<ParseStatus>(ev)) {
      case ParseStatus::Success:
        return "Success";
      case ParseStatus::InvalidPacket:
        return "Invalid packet";
      case ParseStatus::HeaderCRCError:
        return "Header CRC error";
      case ParseStatus::DataCRCError:
        return "Data CRC error";
      case ParseStatus::IncompletePacket:
        return "Incomplete packet";
      case ParseStatus::NotReplyPacket:
        return "Not a reply packet";
      case ParseStatus::PacketStatusError:
        return "Packet status error";
      case ParseStatus::UnknownProtocolIdentifier:
        return "Unknown protocol identifier";
      default:
        return "Unknown status code";
    }
  }
};

inline auto status_code_category() noexcept -> const std::error_category& {
  static StatusCodeCategory instance;
  return instance;
}

inline auto make_error_code(ParseStatus e) noexcept -> std::error_code {
  return {static_cast<int>(e), status_code_category()};
}

}  // namespace spw_rmap

namespace std {

template <>
struct is_error_code_enum<spw_rmap::ParseStatus> : true_type {};

}  // namespace std
