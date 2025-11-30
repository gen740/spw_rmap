// Copyright (c) 2025 Gen
// Licensed under the MIT License. See LICENSE file for details.
#pragma once

#include <system_error>

namespace spw_rmap {

enum class RMAPParseStatus {
  HeaderCRCError = 0,
  DataCRCError = 1,
  IncompletePacket = 2,
  UnknownProtocolIdentifier = 4,
};

class RMAPStatusCodeCategory final : public std::error_category {
 public:
  [[nodiscard]] auto name() const noexcept -> const char* override {
    return "RMAPStatusCode";
  }

  [[nodiscard]] auto message(int ev) const -> std::string override {
    switch (static_cast<RMAPParseStatus>(ev)) {
      case RMAPParseStatus::HeaderCRCError:
        return "Header CRC error";
      case RMAPParseStatus::DataCRCError:
        return "Data CRC error";
      case RMAPParseStatus::IncompletePacket:
        return "Incomplete packet";
      case RMAPParseStatus::UnknownProtocolIdentifier:
        return "Unknown protocol identifier";
      default:
        return "Unknown status code";
    }
  }
};

auto status_code_category() noexcept -> const std::error_category&;

inline auto make_error_code(RMAPParseStatus e) noexcept -> std::error_code {
  return {static_cast<int>(e), status_code_category()};
}

}  // namespace spw_rmap

namespace std {

template <>
struct is_error_code_enum<spw_rmap::RMAPParseStatus> : true_type {};

}  // namespace std
