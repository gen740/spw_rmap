#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <thread>
#include <vector>

#include "spw_rmap/internal/debug.hh"
#include "spw_rmap/internal/tcp_client.hh"

TEST(ThreadSafetyTest, TcpClientSerializesDisconnectedSocketOperations) {
  spw_rmap::internal::TCPClient client("127.0.0.1", "1");
  constexpr std::size_t kIterations = 500;
  std::atomic<std::size_t> unexpected_results{0};
  std::array<uint8_t, 1> send_byte{0x42};
  const bool debug_was_enabled = spw_rmap::debug::IsRuntimeEnabled();
  spw_rmap::debug::Disable();

  auto sender = [&]() -> void {
    for (std::size_t i = 0; i < kIterations; ++i) {
      auto result = client.SendAll(send_byte);
      if (result.has_value() || result.error() != std::errc::not_connected) {
        ++unexpected_results;
      }
    }
  };
  auto receiver = [&]() -> void {
    std::array<uint8_t, 1> receive_byte{};
    for (std::size_t i = 0; i < kIterations; ++i) {
      auto result = client.RecvSome(receive_byte);
      if (result.has_value() || result.error() != std::errc::not_connected) {
        ++unexpected_results;
      }
    }
  };
  auto lifecycle = [&]() -> void {
    for (std::size_t i = 0; i < kIterations; ++i) {
      client.Disconnect();
      auto result = client.Shutdown();
      if (result.has_value() ||
          result.error() != std::errc::bad_file_descriptor) {
        ++unexpected_results;
      }
    }
  };

  std::vector<std::thread> threads;
  threads.emplace_back(sender);
  threads.emplace_back(sender);
  threads.emplace_back(receiver);
  threads.emplace_back(lifecycle);
  for (auto& thread : threads) {
    thread.join();
  }

  spw_rmap::debug::SetRuntimeEnabled(debug_was_enabled);
  EXPECT_EQ(unexpected_results.load(), 0U);
}
