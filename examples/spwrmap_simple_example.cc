#include <array>
#include <chrono>
#include <iostream>
#include <span>

#include "spw_rmap/spw_rmap_tcp_node.hh"
#include "spw_rmap/target_node.hh"

using namespace std::chrono_literals;

auto main() -> int {
  spw_rmap::SpwRmapTCPClient client(
      {.ip_address = "192.168.1.100", .port = "10030"});
  client.setInitiatorLogicalAddress(0xFE);
  // 自動ポーリングモードを有効化
  // それ以外の場合は、外部 thread で定期的に client.poll() を呼び出す必要がある
  client.setAutoPollingMode(true);

  // 接続
  auto res = client.connect(1s);
  if (!res) exit(1);

  // ターゲットノードの作成
  auto target = spw_rmap::TargetNode(0x32);
  target.setTargetAddress(0x06, 0x02);
  target.setReplyAddress(0x01, 0x03);
  constexpr uint32_t addr = 0x44A20000;
  constexpr std::array<uint8_t, 4> payload{0x01, 0x02, 0x03, 0x04};

  // 書き込み
  res = client.write(target, 0x44A20000, payload);
  if (!res) exit(1);

  // 読み込み
  std::array<uint8_t, 4> buf{};
  res = client.read(target, addr, std::span(buf));
  if (!res) exit(1);

  std::cout << "Read:";
  for (auto b : buf) std::cout << " 0x" << std::hex << +b;
  std::cout << std::dec << '\n';

  // シャットダウン
  res = client.shutdown();
  if (!res) exit(1);

  return 0;
}
