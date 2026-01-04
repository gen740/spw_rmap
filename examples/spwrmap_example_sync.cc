#include <array>
#include <chrono>
#include <iostream>
#include <vector>

#include "spw_rmap/spw_rmap_tcp_node.hh"
#include "spw_rmap/target_node.hh"

using namespace std::chrono_literals;

auto main() -> int {
  spw_rmap::SpwRmapTCPClient client(
      {.ip_address = "192.168.1.100", .port = "10030"});
  client.setInitiatorLogicalAddress(0xFE);
  client.setAutoPollingMode(true);
  if (auto res = client.connect(1s); !res.has_value()) {
    std::cerr << "Connect failed: " << res.error().message() << '\n';
    return 1;
  }
  std::cout << "Connected to RMAP bridge (sync example)\n";

  auto target = spw_rmap::TargetNode(0x32);
  target.setTargetAddress(0x06d, 0x02);
  target.setReplyAddress(0x01, 0x03);
  // target.se

  const uint32_t demo_address = 0x44A20000;
  const std::array<uint8_t, 4> payload{0x01, 0x02, 0x03, 0x04};

  if (auto res = client.write(target, demo_address, payload);
      !res.has_value()) {
    std::cerr << "Sync write failed: " << res.error().message() << '\n';
    if (auto shutdown_res = client.shutdown(); !shutdown_res.has_value()) {
      std::cerr << "Shutdown error: " << shutdown_res.error().message() << '\n';
    }
    return 1;
  }
  std::array<uint8_t, 4> buffer{};
  if (auto res = client.read(target, demo_address, std::span(buffer));
      res.has_value()) {
    std::cout << "Sync read:";
    for (auto byte : buffer) {
      std::cout << " 0x" << std::hex << +byte;
    }
    std::cout << std::dec << '\n';
  } else {
    std::cerr << "Sync read failed: " << res.error().message() << '\n';
    if (auto shutdown_res = client.shutdown(); !shutdown_res.has_value()) {
      std::cerr << "Shutdown error: " << shutdown_res.error().message() << '\n';
    }
    return 1;
  }

  if (auto res = client.shutdown(); !res.has_value()) {
    std::cerr << "Shutdown error: " << res.error().message() << '\n';
    return 1;
  }

  return 0;
}
