#include <cstddef>
#include <cstdint>
#include <span>
#include <tuple>

#include "spw_rmap/packet_parser.hh"

extern "C" auto LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size)
    -> int {
  std::ignore = spw_rmap::ParseRMAPPacket(std::span(data, size));
  return 0;
}
