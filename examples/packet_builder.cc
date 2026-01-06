#include "spw_rmap/packet_builder.hh"

#include <array>
#include <iostream>
#include <vector>

namespace {

void printPacket(const std::vector<uint8_t>& packet) {
  std::cout << "Packet bytes:";
  for (auto byte : packet) {
    std::cout << " 0x" << std::hex << std::uppercase << static_cast<int>(byte);
  }
  std::cout << std::dec << '\n';
}

}  // namespace

auto main() -> int {
  std::array<uint8_t, 4> target_address{0x01, 0x02, 0x03, 0x04};
  std::array<uint8_t, 4> reply_address{0x05, 0x06, 0x07, 0x08};

  spw_rmap::ReadPacketConfig config{
      .target_spw_address = target_address,
      .target_logical_address = 0xF2,
      .reply_address = reply_address,
      .initiator_logical_address = 0x35,
      .transaction_id = 0x1234,
      .key = 0xAB,
      .extended_address = 0x00,
      .address = 0x44A40000,
      .data_length = 0x00000004,
      .increment_mode = true,
  };

  std::vector<uint8_t> buffer(config.ExpectedSize());
  auto res = spw_rmap::BuildReadPacket(config, buffer);
  if (!res.has_value()) {
    std::cerr << "Failed to build packet: " << res.error().message() << '\n';
    return 1;
  }

  printPacket(buffer);
  return 0;
}
