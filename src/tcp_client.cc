#include "spw_rmap/internal/tcp_client.hh"

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
#include <span>
#include <sstream>
#include <system_error>

#include "spw_rmap/internal/debug.hh"

namespace spw_rmap::internal {

using namespace std::chrono_literals;

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

static auto close_retry_(int fd) noexcept -> void {
  if (fd >= 0) [[likely]] {
    auto r = 0;
    do {
      r = ::close(fd);
    } while (r < 0 && errno == EINTR);
  }
}

static auto connect_with_timeout_(const int fd, const sockaddr* addr,
                                  socklen_t addrlen,
                                  std::chrono::microseconds timeout) noexcept
    -> std::expected<void, std::error_code> {
  if (timeout < std::chrono::microseconds::zero()) [[unlikely]] {
    spw_rmap::debug::debug("Negative timeout value");
    return std::unexpected{std::make_error_code(std::errc::invalid_argument)};
  }
  const auto ms64 =
      std::chrono::duration_cast<std::chrono::milliseconds>(timeout).count();
  const int ms =
      ms64 > static_cast<long long>(std::numeric_limits<int32_t>::max())
          ? std::numeric_limits<int32_t>::max()
          : static_cast<int>(ms64);

  const int oldfl = ::fcntl(fd, F_GETFL);
  if (oldfl < 0) [[unlikely]] {
    const int err = errno;
    log_errno_("Failed to get fd flags", err);
    return std::unexpected{std::error_code(err, std::system_category())};
  }
  const bool was_blocking = (oldfl & O_NONBLOCK) == 0;
  if (was_blocking) [[unlikely]] {
    if (::fcntl(fd, F_SETFL, oldfl | O_NONBLOCK) < 0) [[unlikely]] {
      const int err = errno;
      log_errno_("Failed to set fd to non-blocking", err);
      return std::unexpected{std::error_code(err, std::system_category())};
    }
  }

  struct Restore {
    Restore(const Restore&) = delete;
    Restore(Restore&&) = delete;
    auto operator=(const Restore&) -> Restore& = delete;
    auto operator=(Restore&&) -> Restore& = delete;
    Restore(int fd, int fl, bool on) : fd(fd), fl(fl), on(on) {}
    int fd;
    int fl;
    bool on;
    ~Restore() {
      if (on) [[unlikely]] {
        (void)::fcntl(fd, F_SETFL, fl);
      }
    }
  } restore{fd, oldfl, was_blocking};

  int rc = 0;
  do {
    rc = ::connect(fd, addr, addrlen);
  } while (rc != 0 && errno == EINTR);

  if (rc == 0) [[likely]] {
    return {};  // Connected immediately.
  }

  const int err = errno;
  if (err != EINPROGRESS) [[unlikely]] {
    log_errno_("Connect failed", err);
    return std::unexpected{std::error_code(err, std::system_category())};
  }
  pollfd pfd{.fd = fd, .events = POLLOUT, .revents = 0};
  int prc = 0;
  do {
    prc = ::poll(&pfd, 1, ms);
  } while (prc < 0 && errno == EINTR);

  if (prc == 0) [[unlikely]] {
    spw_rmap::debug::debug("Connect timed out");
    return std::unexpected{std::error_code(ETIMEDOUT, std::system_category())};
  }
  if (prc < 0) [[unlikely]] {
    const int poll_err = errno;
    log_errno_("Poll failed during connect", poll_err);
    return std::unexpected{std::error_code(poll_err, std::system_category())};
  }

  int soerr = 0;
  auto slen = static_cast<socklen_t>(sizeof(soerr));
  if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) != 0) [[unlikely]] {
    const int soerr_errno = errno;
    log_errno_("getsockopt failed after poll", soerr_errno);
    return std::unexpected{
        std::error_code(soerr_errno, std::system_category())};
  }
  if (soerr != 0) [[unlikely]] {
    log_errno_("Connect failed after poll", soerr);
    return std::unexpected{std::error_code(soerr, std::system_category())};
  }
  return {};
}

static auto set_sockopts(int fd) noexcept
    -> std::expected<void, std::error_code> {
  int yes = 1;
  if (::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes)) != 0)
      [[unlikely]] {
    const int err = errno;
    log_errno_("Failed to set TCP_NODELAY", err);
    return std::unexpected{std::error_code(err, std::system_category())};
  }
#ifdef __APPLE__
  if (::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes)) != 0)
      [[unlikely]] {
    const int err = errno;
    log_errno_("Failed to set SO_NOSIGPIPE", err);
    return std::unexpected{std::error_code(err, std::system_category())};
  }
#endif
  const int fdflags = ::fcntl(fd, F_GETFD);
  if (fdflags < 0 || ::fcntl(fd, F_SETFD, fdflags | FD_CLOEXEC) < 0)
      [[unlikely]] {
    const int err = errno;
    log_errno_("Failed to set FD_CLOEXEC", err);
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
    log_errno_("poll failed while checking client socket", err);
    return false;
  }
  if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL
#ifdef POLLRDHUP
                     | POLLRDHUP
#endif
                     )) [[unlikely]] {
    return false;
  }
  if ((pfd.revents & POLLIN) != 0) [[unlikely]] {
    uint8_t tmp{};
    const ssize_t n = ::recv(fd, &tmp, 1, MSG_PEEK | MSG_DONTWAIT);
    if (n == 0) [[unlikely]] {
      return false;
    }
    const int err = errno;
    if (n < 0 && err != EAGAIN && err != EWOULDBLOCK && err != EINTR)
        [[unlikely]] {
      log_errno_("recv peek failed while checking client socket", err);
      return false;
    }
  }
  return true;
}

TCPClient::~TCPClient() {
  disconnect();
  fd_ = -1;
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

[[nodiscard]] auto TCPClient::connect(
    std::chrono::microseconds timeout) noexcept
    -> std::expected<void, std::error_code> {
  if (fd_ >= 0) [[unlikely]] {
    spw_rmap::debug::debug("Already connected");
    return std::unexpected{std::make_error_code(std::errc::already_connected)};
  }
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  addrinfo* res = nullptr;
  if (int rc = ::getaddrinfo(std::string(ip_address_).c_str(),
                             std::string(port_).c_str(), &hints, &res);
      rc != 0) [[unlikely]] {
    if (rc == EAI_SYSTEM) [[unlikely]] {
      const int err = errno;
      log_errno_("getaddrinfo system error", err);
      return std::unexpected{std::error_code(err, std::system_category())};
    } else {
      spw_rmap::debug::debug("getaddrinfo error: ", ::gai_strerror(rc));
      return std::unexpected{std::error_code(rc, gai_category())};
    }
  }

  std::expected<void, std::error_code> last =
      std::unexpected(std::make_error_code(std::errc::invalid_argument));

  for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
    fd_ = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd_ < 0) [[unlikely]] {
      const int err = errno;
      log_errno_("Failed to create client socket", err);
      last = std::unexpected{std::error_code(err, std::system_category())};
      close_retry_(fd_);
      fd_ = -1;
      continue;
    }
    last = internal::set_sockopts(fd_).and_then([this, timeout, ai]() -> auto {
      return connect_with_timeout_(fd_, ai->ai_addr, ai->ai_addrlen, timeout);
    });
    if (!last.has_value()) [[unlikely]] {
      close_retry_(fd_);
      fd_ = -1;
      continue;
    }
    break;  // success
  }

  ::freeaddrinfo(res);
  if (fd_ < 0) [[unlikely]] {
    fd_ = -1;
  }
  return last;
}

auto TCPClient::ensureConnect(std::chrono::microseconds timeout) noexcept
    -> std::expected<void, std::error_code> {
  if (fd_ >= 0 && socket_alive_(fd_)) [[likely]] {
    return {};
  }
  if (fd_ >= 0) [[unlikely]] {
    spw_rmap::debug::debug("Existing connection unhealthy, reconnecting");
    disconnect();
  }
  return connect(timeout);
}

auto TCPClient::disconnect() noexcept -> void {
  close_retry_(fd_);
  fd_ = -1;
}

auto TCPClient::setSendTimeout(std::chrono::microseconds timeout) noexcept
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

  if (::setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0)
      [[unlikely]] {
    const int err = errno;
    log_errno_("Failed to set send timeout", err);
    return std::unexpected{std::error_code(err, std::system_category())};
  }
  return {};
}

auto TCPClient::setReceiveTimeout(std::chrono::microseconds timeout) noexcept
    -> std::expected<void, std::error_code> {
  if (timeout < std::chrono::microseconds::zero()) [[unlikely]] {
    spw_rmap::debug::debug("Negative timeout value");
    return std::unexpected{std::make_error_code(std::errc::invalid_argument)};
  }
  const auto tv_sec = static_cast<time_t>(
      std::chrono::duration_cast<std::chrono::seconds>(timeout).count());
  const auto tv_usec = static_cast<suseconds_t>(timeout.count() % 1'000'000);
  timeval tv{};
  tv.tv_sec = tv_sec;
  tv.tv_usec = tv_usec;
  if (::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
      [[unlikely]] {
    const int err = errno;
    log_errno_("Failed to set receive timeout", err);
    return std::unexpected{std::error_code(err, std::system_category())};
  }
  return {};
}

auto TCPClient::sendAll(std::span<const uint8_t> data) noexcept
    -> std::expected<void, std::error_code> {
  if (fd_ < 0) [[unlikely]] {
    spw_rmap::debug::debug("Not connected");
    return std::unexpected{std::make_error_code(std::errc::not_connected)};
  }
  bool retried_zero = false;
  while (!data.empty()) {
#ifndef __APPLE__
    constexpr int kFlags = MSG_NOSIGNAL;
#else
    constexpr int kFlags = 0;
#endif
    const ssize_t n = ::send(fd_, data.data(), data.size(), kFlags);
    if (n < 0) [[unlikely]] {
      const int err = errno;
      if (err == EINTR) [[unlikely]] {
        continue;
      }
      if (err == EAGAIN || err == EWOULDBLOCK) [[unlikely]] {
        spw_rmap::debug::debug("Send would block, timing out");
        return std::unexpected{std::make_error_code(std::errc::timed_out)};
      }
      log_errno_("Send failed", err);
      return std::unexpected{std::error_code(err, std::system_category())};
    }
    if (n == 0) [[unlikely]] {
      if (retried_zero) [[unlikely]] {
        spw_rmap::debug::debug("Send returned zero twice, treating as error");
        return std::unexpected{std::make_error_code(std::errc::io_error)};
      }
      pollfd pfd{.fd = fd_, .events = POLLOUT, .revents = 0};
      int prc = 0;
      do {
        prc = ::poll(&pfd, 1, 10);
      } while (prc < 0 && errno == EINTR);

      if (prc == 0) [[unlikely]] {
        spw_rmap::debug::debug("Poll timed out after send returned zero");
        return std::unexpected{std::make_error_code(std::errc::timed_out)};
      }
      if (prc < 0) [[unlikely]] {
        const int poll_err = errno;
        log_errno_("Poll failed after send returned zero", poll_err);
        return std::unexpected{
            std::error_code(poll_err, std::system_category())};
      }
      if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) [[unlikely]] {
        spw_rmap::debug::debug(
            "Socket error after send returned zero, treating as closed");
        return std::unexpected{
            std::make_error_code(std::errc::connection_aborted)};
      }
      if ((pfd.revents & POLLOUT) == 0) [[unlikely]] {
        spw_rmap::debug::debug(
            "Socket not writable after send returned zero, treating as error");
        return std::unexpected{std::make_error_code(std::errc::io_error)};
      }
      retried_zero = true;
      continue;
    }
    data = data.subspan(static_cast<size_t>(n));
  }
  return {};
}

auto TCPClient::recvSome(std::span<uint8_t> buf) noexcept
    -> std::expected<size_t, std::error_code> {
  if (buf.empty()) [[unlikely]] {
    return 0U;  // Nothing to receive
  }
  for (;;) {
    const ssize_t n = ::recv(fd_, buf.data(), buf.size(), 0);
    if (n < 0) [[unlikely]] {
      const int err = errno;
      if (err == EINTR) [[unlikely]] {
        continue;
      }
      if (err == EAGAIN || err == EWOULDBLOCK) [[unlikely]] {
        spw_rmap::debug::debug("Receive would block, timing out");
        return std::unexpected{std::make_error_code(std::errc::timed_out)};
      }
      log_errno_("Receive failed", err);
      return std::unexpected{std::error_code(err, std::system_category())};
    } else if (n == 0) [[unlikely]] {
      spw_rmap::debug::debug("Connection closed by peer");
      return std::unexpected{std::make_error_code(std::errc::io_error)};
    }
    return static_cast<size_t>(n);
  }
}

auto TCPClient::shutdown() noexcept -> std::expected<void, std::error_code> {
  if (fd_ < 0) [[unlikely]] {
    spw_rmap::debug::debug("Not connected");
    return std::unexpected(
        std::make_error_code(std::errc::bad_file_descriptor));
  }
  if (::shutdown(fd_, SHUT_RDWR) < 0) [[unlikely]] {
    const int err = errno;
    log_errno_("Shutdown failed", err);
    return std::unexpected(std::error_code(err, std::generic_category()));
  }
  return {};
}

}  // namespace spw_rmap::internal
