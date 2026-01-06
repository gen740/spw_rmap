#include <gtest/gtest.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <future>
#include <optional>
#include <random>
#include <span>
#include <spw_rmap/internal/tcp_client.hh>
#include <spw_rmap/internal/tcp_server.hh>
#include <string>
#include <thread>
#include <vector>

using spw_rmap::internal::TCPClient;
using spw_rmap::internal::TCPServer;

using namespace std::chrono_literals;

// Helper: bind to 127.0.0.1:0 to get an available port, then close.
static auto pick_free_port() -> uint16_t {
  const int fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0) {
    throw std::system_error(errno, std::system_category(), "socket");
  }
  int r = 0;
  sockaddr_in sin{};
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sin.sin_port = htons(0);
  r = ::bind(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin));  // NOLINT
  if (r != 0) {
    const int e = errno;
    (void)::close(fd);
    throw std::system_error(e, std::system_category(), "bind");
  }
  socklen_t sl = sizeof(sin);
  r = ::getsockname(fd, reinterpret_cast<sockaddr*>(&sin), &sl);  // NOLINT
  if (r != 0) {
    const int e = errno;
    (void)::close(fd);
    throw std::system_error(e, std::system_category(), "getsockname");
  }
  const uint16_t port = ntohs(sin.sin_port);
  do {  // NOLINT
    r = ::close(fd);
  } while (r < 0 && errno == EINTR);
  return port;
}

std::mt19937 rng(std::random_device{}());  // NOLINT

static void close_fd_retry(int fd) {
  if (fd < 0) {
    return;
  }
  int r = 0;
  do {
    r = ::close(fd);
  } while (r < 0 && errno == EINTR);
}

TEST(TcpClientServer, ServerRecieve) {
  size_t TEST_BUFFER_SIZE = 1024UL;
  uint16_t port = 0;
  try {
    port = pick_free_port();
  } catch (const std::system_error& e) {
    if (e.code() == std::errc::operation_not_permitted) {
      GTEST_SKIP() << "Skipping due to sandbox restriction: " << e.what();
    }
    throw;
  }

  std::atomic<bool> server_stop{false};
  std::vector<uint8_t> server_recv_buf;

  server_recv_buf.resize(TEST_BUFFER_SIZE);
  bool server_emit_error = false;

  std::thread th([&]() -> void {
    try {
      std::string port_str = std::to_string(port);
      TCPServer server("127.0.0.1", port_str);
      auto res = server.AcceptOnce();
      if (!res.has_value()) {
        FAIL() << "Failed to accept connection: " << res.error().message();
      }
      auto total_recvd = 0U;

      std::vector<uint8_t> buf;
      buf.resize(16);
      while (!server_stop.load(std::memory_order_acquire)) {
        auto n = server.RecvSome(buf);
        if (!n.has_value()) {
          FAIL() << "Server recv_some failed: " << n.error().message();
        }
        std::ranges::copy(std::span(buf).subspan(0, *n),
                          server_recv_buf.begin() + total_recvd);
        total_recvd += *n;
        if (total_recvd == TEST_BUFFER_SIZE) {
          break;
        }
      }
    } catch (const std::system_error& e) {
      std::puts("Server thread error");
      std::puts(e.what());
      server_emit_error = true;
    }
  });

  std::string port_str = std::to_string(port);
  TCPClient client("localhost", port_str);
  auto res = client.Connect(500ms);
  if (!res.has_value()) {
    FAIL() << "Failed to connect to server: " << res.error().message();
  }

  std::vector<uint8_t> msg;
  msg.resize(TEST_BUFFER_SIZE);

  for (auto& byte : msg) {
    byte = static_cast<uint8_t>(std::uniform_int_distribution<>(0, 255)(rng));
  }

  size_t mes_size_sent = 0;
  while (mes_size_sent < msg.size()) {
    size_t mes_size = std::uniform_int_distribution<>(1, 32)(rng);
    if (mes_size_sent + mes_size > msg.size()) {
      mes_size = msg.size() - mes_size_sent;
    }
    auto res = client.SendAll(
        std::span<const uint8_t>(msg.data() + mes_size_sent, mes_size));
    if (!res.has_value()) {
      FAIL() << "Client send_all failed: " << res.error().message();
    }
    mes_size_sent += mes_size;
  }
  std::this_thread::sleep_for(100ms);  // Give server time to process.

  server_stop.store(true, std::memory_order_release);
  EXPECT_EQ(server_recv_buf, msg);

  if (th.joinable()) {
    th.join();
  }
  EXPECT_FALSE(server_emit_error)
      << "Server thread emitted an error during execution.";
}

TEST(TcpClientServer, ClientRecieve) {
  size_t TEST_BUFFER_SIZE = 1024UL;
  uint16_t port = 0;
  try {
    port = pick_free_port();
  } catch (const std::system_error& e) {
    if (e.code() == std::errc::operation_not_permitted) {
      GTEST_SKIP() << "Skipping due to sandbox restriction: " << e.what();
    }
    throw;
  }

  std::atomic<bool> server_stop{false};

  std::vector<uint8_t> msg;
  msg.resize(TEST_BUFFER_SIZE);
  for (auto& byte : msg) {
    byte = static_cast<uint8_t>(std::uniform_int_distribution<>(0, 255)(rng));
  }
  bool server_emit_error = false;
  std::thread th([&]() -> void {
    try {
      std::string port_str = std::to_string(port);
      TCPServer server("127.0.0.1", port_str);
      auto res = server.AcceptOnce();
      if (!res.has_value()) {
        FAIL() << "Failed to accept connection: " << res.error().message();
      }
      size_t mes_size_sent = 0;
      while (mes_size_sent < msg.size()) {
        size_t mes_size = std::uniform_int_distribution<>(1, 32)(rng);
        if (mes_size_sent + mes_size > msg.size()) {
          mes_size = msg.size() - mes_size_sent;
        }
        auto res = server.SendAll(
            std::span<const uint8_t>(msg.data() + mes_size_sent, mes_size));
        if (!res.has_value()) {
          FAIL() << "Server send_all failed: " << res.error().message();
        }
        mes_size_sent += mes_size;
      }
    } catch (const std::system_error& e) {
      std::puts("Server thread error");
      std::puts(e.what());
      server_emit_error = true;
    }
  });

  std::string port_str = std::to_string(port);
  TCPClient client("localhost", port_str);
  auto res = client.Connect(500ms);
  if (!res.has_value()) {
    FAIL() << "Failed to connect to server: " << res.error().message();
  }
  std::vector<uint8_t> client_recv_buf;
  client_recv_buf.resize(TEST_BUFFER_SIZE);

  std::vector<uint8_t> buf;
  buf.resize(16);
  auto total_recvd = 0U;
  while (true) {
    auto n = client.RecvSome(buf);
    if (!n.has_value()) {
      FAIL() << "Client recv_some failed: " << n.error().message();
    }
    std::ranges::copy(std::span(buf).subspan(0, *n),
                      client_recv_buf.begin() + total_recvd);
    total_recvd += *n;
    if (total_recvd == TEST_BUFFER_SIZE) {
      break;
    }
  }
  server_stop.store(true, std::memory_order_release);
  EXPECT_EQ(msg, client_recv_buf);
  if (th.joinable()) {
    th.join();
  }
  EXPECT_FALSE(server_emit_error)
      << "Server thread emitted an error during execution.";
}

TEST(TcpClientServer, ConnectReconnectsAfterDrop) {
  uint16_t port = 0;
  try {
    port = pick_free_port();
  } catch (const std::system_error& e) {
    if (e.code() == std::errc::operation_not_permitted) {
      GTEST_SKIP() << "Skipping due to sandbox restriction: " << e.what();
    }
    throw;
  }

  std::atomic<bool> first_connection_closed{false};
  std::atomic<bool> second_connection_established{false};
  std::atomic<bool> server_stop{false};
  std::optional<std::string> server_error;
  std::promise<void> server_ready_promise;
  std::atomic<bool> server_ready_notified{false};
  auto server_ready = server_ready_promise.get_future();

  std::thread server_thread([&, port]() -> void {
    const auto notify_ready = [&]() -> void {
      if (!server_ready_notified.exchange(true, std::memory_order_acq_rel)) {
        server_ready_promise.set_value();
      }
    };
    const auto set_error = [&](const char* label, int err) -> void {
      server_error = std::string(label) + ": " +
                     std::error_code(err, std::system_category()).message();
    };
    int listen_fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd < 0) {
      set_error("socket", errno);
      notify_ready();
      return;
    }
    int yes = 1;
    (void)::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(port);
    if (::bind(listen_fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)) !=
        0) {
      set_error("bind", errno);
      close_fd_retry(listen_fd);
      notify_ready();
      return;
    }
    if (::listen(listen_fd, SOMAXCONN) != 0) {
      set_error("listen", errno);
      close_fd_retry(listen_fd);
      notify_ready();
      return;
    }

    notify_ready();

    int connections = 0;
    while (!server_stop.load(std::memory_order_acquire)) {
      int client_fd = ::accept(listen_fd, nullptr, nullptr);
      if (client_fd < 0) {
        if (errno == EINTR) {
          continue;
        }
        set_error("accept", errno);
        break;
      }
      if (server_stop.load(std::memory_order_acquire)) {
        close_fd_retry(client_fd);
        break;
      }
      ++connections;
      if (connections == 1) {
        close_fd_retry(client_fd);
        first_connection_closed.store(true, std::memory_order_release);
        continue;
      }
      second_connection_established.store(true, std::memory_order_release);
      while (!server_stop.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
      }
      close_fd_retry(client_fd);
      break;
    }
    close_fd_retry(listen_fd);
  });

  TCPClient client("127.0.0.1", std::to_string(port));

  struct CleanupGuard {
    std::atomic<bool>& stop_flag;
    std::thread* thread;
    TCPClient& client_ref;
    uint16_t port;
    bool skip{false};
    ~CleanupGuard() {
      if (skip) {
        return;
      }
      stop_flag.store(true, std::memory_order_release);
      int tmp = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      if (tmp >= 0) {
        sockaddr_in sin{};
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sin.sin_port = htons(port);
        (void)::connect(tmp, reinterpret_cast<sockaddr*>(&sin), sizeof(sin));
        close_fd_retry(tmp);
      }
      client_ref.Disconnect();
      if (thread != nullptr && thread->joinable()) {
        thread->join();
      }
    }
  } guard{server_stop, &server_thread, client, port};

  ASSERT_EQ(server_ready.wait_for(std::chrono::seconds{1}),
            std::future_status::ready)
      << "Server did not start listening in time";

  auto first_res = client.Connect(500ms);
  ASSERT_TRUE(first_res.has_value())
      << "Initial connect failed: " << first_res.error().message();

  for (int i = 0;
       i < 100 && !first_connection_closed.load(std::memory_order_acquire);
       ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
  }
  ASSERT_TRUE(first_connection_closed.load(std::memory_order_acquire))
      << "Server did not close the first connection in time";

  auto reconnect_res = client.Connect(500ms);
  ASSERT_TRUE(reconnect_res.has_value())
      << "Reconnect attempt failed: " << reconnect_res.error().message();

  for (int i = 0; i < 100 && !second_connection_established.load(
                                 std::memory_order_acquire);
       ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
  }
  ASSERT_TRUE(second_connection_established.load(std::memory_order_acquire))
      << "Server did not accept the reconnection";

  client.Disconnect();
  server_stop.store(true, std::memory_order_release);
  if (server_thread.joinable()) {
    server_thread.join();
  }
  guard.skip = true;

  ASSERT_FALSE(server_error.has_value())
      << "Server thread error: " << *server_error;
}
