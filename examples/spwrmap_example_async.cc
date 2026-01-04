#include <array>
#include <chrono>
#include <iostream>
#include <thread>

#include "spw_rmap/spw_rmap_tcp_node.hh"
#include "spw_rmap/target_node.hh"

using namespace std::chrono_literals;

auto main() -> int {
  spw_rmap::SpwRmapTCPClient client(
      {.ip_address = "192.168.1.100", .port = "10030"});
  client.setInitiatorLogicalAddress(0xFE);
  if (auto res = client.connect(1s); !res.has_value()) {
    std::cerr << "Connect failed: " << res.error().message() << '\n';
    return 1;
  }
  std::cout << "Connected to RMAP bridge (async example)\n";

  auto target = spw_rmap::TargetNode(0x32)
                    .setTargetAddress(0x06, 0x02)
                    .setReplyAddress(0x01, 0x03);

  std::thread loop([&client]() -> void {
    auto res = client.runLoop();
    if (!res.has_value()) {
      std::cerr << "runLoop error: " << res.error().message() << '\n';
    }
  });

  const uint32_t demo_address = 0x44A20000;
  const std::array<uint8_t, 4> payload{0x01, 0x02, 0x03, 0x04};

  bool ok = true;
  if (auto res = client.write(target, demo_address, payload);
      !res.has_value()) {
    std::cerr << "Sync write failed: " << res.error().message() << '\n';
    ok = false;
  } else {
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
      ok = false;
    }
  }

  if (ok) {
    auto write_async_res = client.writeAsync(
        target, demo_address, payload,
        [](const std::expected<spw_rmap::Packet, std::error_code> packet)
            -> void {
          if (packet.has_value()) {
            std::cout << "Async write completed\n";
          } else {
            std::cerr << "Async write error: " << packet.error().message()
                      << '\n';
          }
        });
    if (!write_async_res.has_value()) {
      std::cerr << "Async write failed\n";
      ok = false;
    }
  }

  if (ok) {
    auto read_res = client.readAsync(
        target, demo_address, payload.size(),
        [](std::expected<spw_rmap::Packet, std::error_code> packet) -> void {
          if (packet.has_value()) {
            std::cout << "Async read returned " << packet->data.size()
                      << " bytes\n";
          }
        });
    if (!read_res.has_value()) {
      std::cerr << "Async read failed\n";
    }
  }

  if (auto res = client.shutdown(); !res.has_value()) {
    std::cerr << "Shutdown error: " << res.error().message() << '\n';
  }
  if (loop.joinable()) {
    loop.join();
  }
  return 0;
}
