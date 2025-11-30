#include "spw_rmap/internal/tcp_server.hh"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/fcntl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <span>
#include <sstream>
#include <string>
#include <system_error>

#include "spw_rmap/internal/debug.hh"

namespace spw_rmap::internal {

namespace {
inline void log_errno_(const char* msg, int err) noexcept {
  if constexpr (!spw_rmap::debug::enabled) {
    (void)msg;
    (void)err;
    return;
  }
  if (!spw_rmap::debug::is_runtime_enabled()) [[likely]] {
    (void)msg;
    (void)err;
    return;
  }
  const std::error_code ec(err, std::system_category());
  std::ostringstream oss;
  oss << msg << ": " << ec.message() << " (errno=" << ec.value() << ")";
  spw_rmap::debug::debug(oss.str());
}
}  // namespace

static inline auto set_listening_sockopt(int fd)
    -> std::expected<void, std::error_code> {
  // Allow quick rebinding after restart.
  int yes = 1;
  (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef SO_REUSEPORT
  (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif
  // CLOEXEC for listen fd as well.
  const int fdflags = ::fcntl(fd, F_GETFD);
  if (fdflags < 0) [[unlikely]] {
    const int err = errno;
    log_errno_("Failed to get FD flags on listening socket", err);
    return std::unexpected{std::error_code(err, std::system_category())};
  }
  if (::fcntl(fd, F_SETFD, fdflags | FD_CLOEXEC) < 0) [[unlikely]] {
    const int err = errno;
    log_errno_("Failed to set FD_CLOEXEC on listening socket", err);
    return std::unexpected{std::error_code(err, std::system_category())};
  }
  return {};
}

static inline auto server_set_sockopts(int fd)
    -> std::expected<void, std::error_code> {
  int yes = 1;
  // Disable Nagle for latency-sensitive traffic.
  if (::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes)) != 0)
      [[unlikely]] {
    const int err = errno;
    log_errno_("Failed to set TCP_NODELAY", err);
    return std::unexpected{std::error_code(err, std::system_category())};
  }
#ifdef __APPLE__
  // Avoid SIGPIPE on write-side errors.
  if (::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes)) != 0)
      [[unlikely]] {
    const int err = errno;
    log_errno_("Failed to set SO_NOSIGPIPE", err);
    return std::unexpected{std::error_code(err, std::system_category())};
  }
#endif
  // Ensure close-on-exec (harmless if already set).
  const int fdflags = ::fcntl(fd, F_GETFD);
  if (fdflags < 0) [[unlikely]] {
    const int err = errno;
    log_errno_("Failed to get FD flags on server socket", err);
    return std::unexpected{std::error_code(err, std::system_category())};
  }
  if (::fcntl(fd, F_SETFD, fdflags | FD_CLOEXEC) < 0) [[unlikely]] {
    const int err = errno;
    log_errno_("Failed to set FD_CLOEXEC on server socket", err);
    return std::unexpected{std::error_code(err, std::system_category())};
  }
  return {};
}

static auto socket_alive_(int fd) noexcept -> bool {
  if (fd < 0) [[unlikely]] {
    return false;
  }
  pollfd pfd{
      .fd = fd,
      .events = POLLIN | POLLERR | POLLHUP
#ifdef POLLRDHUP
                | POLLRDHUP
#endif
      ,
      .revents = 0,
  };
  int prc = 0;
  do {
    prc = ::poll(&pfd, 1, 0);
  } while (prc < 0 && errno == EINTR);
  if (prc < 0) [[unlikely]] {
    const int err = errno;
    log_errno_("poll failed while checking server socket", err);
    return false;
  }
  if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL
#ifdef POLLRDHUP
                     | POLLRDHUP
#endif
                     )) {
    return false;
  }
  if ((pfd.revents & POLLIN) != 0) [[unlikely]] {
    uint8_t tmp{};
    const ssize_t n = ::recv(fd, &tmp, 1, MSG_PEEK | MSG_DONTWAIT);
    if (n == 0) {
      return false;
    }
    const int err = errno;
    if (n < 0 && err != EAGAIN && err != EWOULDBLOCK && err != EINTR) {
      log_errno_("recv peek failed while checking server socket", err);
      return false;
    }
  }
  return true;
}

auto TCPServer::close_retry_(int fd) noexcept -> void {
  if (fd < 0) [[unlikely]] {
    return;
  }
  int r = 0;
  do {
    r = ::close(fd);
  } while (r < 0 && errno == EINTR);
}

struct gai_category_t final : std::error_category {
  [[nodiscard]] auto name() const noexcept -> const char* override {
    return "gai";
  }
  [[nodiscard]] auto message(int ev) const -> std::string override {
    return ::gai_strerror(ev);
  }
};

static inline auto gai_category() noexcept -> const std::error_category& {
  static const gai_category_t cat{};
  return cat;
}

auto TCPServer::accept_once() noexcept -> std::expected<void, std::error_code> {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;  // IPv4/IPv6 both
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;  // for bind

  addrinfo* res = nullptr;
  if (int rc = ::getaddrinfo(std::string(bind_address_).c_str(),
                             std::string(port_).c_str(), &hints, &res);
      rc != 0) [[unlikely]] {
    spw_rmap::debug::debug("getaddrinfo error: ", ::gai_strerror(rc));
    return std::unexpected{std::error_code(rc, gai_category())};
  }
  std::expected<void, std::error_code> last =
      std::unexpected(std::make_error_code(std::errc::invalid_argument));

  for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
    listen_fd_ = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (listen_fd_ < 0) [[unlikely]] {
      const int err = errno;
      log_errno_("Failed to create listening socket", err);
      last = std::unexpected{std::error_code(err, std::system_category())};
      continue;
    }

    last = internal::set_listening_sockopt(listen_fd_);
    if (!last.has_value()) {
      close_retry_(listen_fd_);
      listen_fd_ = -1;
      continue;
    }
    if (::bind(listen_fd_, ai->ai_addr, ai->ai_addrlen) != 0) [[unlikely]] {
      const int err = errno;
      log_errno_("Failed to bind listening socket", err);
      last = std::unexpected{std::error_code(err, std::system_category())};
      close_retry_(listen_fd_);
      listen_fd_ = -1;
      continue;
    }
    if (::listen(listen_fd_, SOMAXCONN) != 0) [[unlikely]] {
      const int err = errno;
      log_errno_("Failed to listen on socket", err);
      last = std::unexpected{std::error_code(err, std::system_category())};
      close_retry_(listen_fd_);
      listen_fd_ = -1;
      continue;
    }

    for (;;) {
      client_fd_ = ::accept(listen_fd_, nullptr, nullptr);
      if (client_fd_ < 0 && errno == EINTR) [[unlikely]] {
        continue;
      }
      break;
    }
    if (client_fd_ < 0) [[unlikely]] {
      const int err = errno;
      log_errno_("Failed to accept client socket", err);
      last = std::unexpected{std::error_code(err, std::system_category())};
      close_retry_(listen_fd_);
      listen_fd_ = -1;
      continue;
    }

    last =
        internal::server_set_sockopts(client_fd_)
            .or_else(
                [this](const auto& ec) -> std::expected<void, std::error_code> {
                  close_retry_(listen_fd_);
                  listen_fd_ = -1;
                  close_retry_(client_fd_);
                  client_fd_ = -1;
                  spw_rmap::debug::debug([ec]() {
                    std::ostringstream oss;
                    oss << "Failed to set socket options on accepted socket: "
                        << ec.message() << " (errno=" << ec.value() << ")";
                    return oss.str();
                  }());
                  return std::unexpected{ec};
                });
  }
  ::freeaddrinfo(res);
  if (client_fd_ < 0) [[unlikely]] {
    client_fd_ = -1;
    return last;
  }
  close_retry_(listen_fd_);
  listen_fd_ = -1;
  return {};
}

auto TCPServer::ensureConnect() noexcept
    -> std::expected<void, std::error_code> {
  if (client_fd_ >= 0 && socket_alive_(client_fd_)) [[likely]] {
    return {};
  }
  if (client_fd_ >= 0) [[likely]] {
    spw_rmap::debug::debug("Client socket unhealthy, reopening server socket");
    close_retry_(client_fd_);
    client_fd_ = -1;
  }
  return accept_once();
}

TCPServer::~TCPServer() noexcept {
  close_retry_(client_fd_);
  client_fd_ = -1;
  close_retry_(listen_fd_);
  listen_fd_ = -1;
}

auto TCPServer::setSendTimeout(std::chrono::microseconds timeout) noexcept
    -> std::expected<void, std::error_code> {
  if (timeout < std::chrono::microseconds::zero()) [[unlikely]] {
    spw_rmap::debug::debug("Negative timeout value");
    return std::unexpected{std::make_error_code(std::errc::invalid_argument)};
  }
  const auto tv_sec = static_cast<time_t>(
      std::chrono::duration_cast<std::chrono::seconds>(timeout).count());
  const auto tv_usec = static_cast<suseconds_t>(timeout.count() % 1000000);

  timeval tv{};
  tv.tv_sec = tv_sec;
  tv.tv_usec = tv_usec;

  if (::setsockopt(client_fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0)
      [[unlikely]] {
    const int err = errno;
    log_errno_("Failed to set send timeout", err);
    return std::unexpected{std::error_code(err, std::system_category())};
  }
  return {};
}

auto TCPServer::setReceiveTimeout(std::chrono::microseconds timeout) noexcept
    -> std::expected<void, std::error_code> {
  if (timeout < std::chrono::microseconds::zero()) [[unlikely]] {
    spw_rmap::debug::debug("Negative timeout value");
    return std::unexpected{std::make_error_code(std::errc::invalid_argument)};
  }
  const auto tv_sec = static_cast<time_t>(
      std::chrono::duration_cast<std::chrono::seconds>(timeout).count());
  const auto tv_usec = static_cast<suseconds_t>(timeout.count() % 1000000);

  timeval tv{};
  tv.tv_sec = tv_sec;
  tv.tv_usec = tv_usec;

  if (::setsockopt(client_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
      [[unlikely]] {
    const int err = errno;
    log_errno_("Failed to set receive timeout", err);
    return std::unexpected{std::error_code(err, std::system_category())};
  }
  return {};
}

auto TCPServer::sendAll(std::span<const uint8_t> data) noexcept
    -> std::expected<void, std::error_code> {
  while (!data.empty()) {
#ifndef __APPLE__
    constexpr int kFlags = MSG_NOSIGNAL;
#else
    constexpr int kFlags = 0;  // SO_NOSIGPIPE is set in set_sockopts()
#endif
    const ssize_t n = ::send(client_fd_, data.data(), data.size(), kFlags);
    if (n < 0) [[unlikely]] {
      const int err = errno;
      if (err == EINTR) {
        continue;
      }
      if (err == EAGAIN || err == EWOULDBLOCK) {
        spw_rmap::debug::debug("Send would block, timing out");
        return std::unexpected{std::make_error_code(std::errc::timed_out)};
      }
      log_errno_("Send failed", err);
      return std::unexpected{std::error_code(err, std::system_category())};
    }
    if (n == 0) {
      continue;  // not EOF for send(); retry
    }
    data = data.subspan(static_cast<std::size_t>(n));
  }
  return {};
}

auto TCPServer::recvSome(std::span<uint8_t> buf) noexcept
    -> std::expected<size_t, std::error_code> {
  if (buf.empty()) {
    return 0U;
  }
  for (;;) {
    const ssize_t n = ::recv(client_fd_, buf.data(), buf.size(), 0);
    if (n < 0) [[unlikely]] {
      const int err = errno;
      if (err == EINTR) {
        continue;
      }
      if (err == EAGAIN || err == EWOULDBLOCK) {
        spw_rmap::debug::debug("Receive would block, timing out");
        return std::unexpected{std::make_error_code(std::errc::timed_out)};
      }
      log_errno_("Receive failed", err);
      return std::unexpected{std::error_code(err, std::system_category())};
    }
    return static_cast<std::size_t>(n);  // 0 -> EOF
  }
}

auto TCPServer::shutdown() noexcept -> std::expected<void, std::error_code> {
  if (client_fd_ < 0) [[unlikely]] {
    spw_rmap::debug::debug("Client socket not connected");
    return std::unexpected(
        std::make_error_code(std::errc::bad_file_descriptor));
  }
  if (::shutdown(client_fd_, SHUT_RDWR) < 0) [[unlikely]] {
    const int err = errno;
    log_errno_("Failed to shutdown client socket", err);
    return std::unexpected(std::error_code(err, std::generic_category()));
  }
  return {};
}

};  // namespace spw_rmap::internal
