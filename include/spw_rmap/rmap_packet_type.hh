// Copyright (c) 2025 Gen
// Licensed under the MIT License. See LICENSE file for details.
#pragma once

#include <cstdint>

namespace spw_rmap {

inline constexpr uint8_t kRmapProtocolIdentifier = 0x01;

enum class RMAPPacketType : uint8_t {
  kCommand = 0b01000000,
  kReply = 0b00000000,
};

enum class RMAPCommandCode : uint8_t {
  kWrite = 0b00100000,                  // Read operation
  kVerifyDataBeforeWrite = 0b00010000,  // Write operation
  kReply = 0b00001000,                  // Read-Modify-Write operation
  kIncrementAddress = 0b00000100,       // Incremental address operation
};

}  // namespace spw_rmap
