#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <numeric>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/resource.h>
#endif

#include "spw_rmap/spw_rmap_tcp_node.hh"
#include "spw_rmap/target_node.hh"

using namespace std::chrono_literals;

namespace {

constexpr uint8_t kInitiatorLogicalAddress = 0xFE;
constexpr uint8_t kTargetLogicalAddress = 0xFE;
constexpr std::size_t kChunkSize = 1024;

using Clock = std::chrono::steady_clock;

struct Options {
  std::string ip{"127.0.0.1"};
  std::string port{"10030"};
  std::vector<uint8_t> target_address;
  std::vector<uint8_t> reply_address;
  std::optional<std::size_t> ntimes;
  std::optional<std::size_t> nbytes;
  std::optional<uint32_t> start_address;
  std::optional<std::string> out_path;
};

void printUsage(const char* program) {
  std::cerr << "Usage: " << program << '\n'
            << "  --ip <addr> --port <port> --target-address <bytes...>\n"
            << "  --reply-address <bytes...> --ntimes <count> --nbytes <size>\n"
            << "  --start_address <addr>\n";
}

auto parseUnsigned(std::string_view token, unsigned long long max_value)
    -> std::optional<unsigned long long> {
  try {
    std::string temp(token);
    size_t idx = 0;
    auto value = std::stoull(temp, &idx, 0);
    if (idx != temp.size() || value > max_value) {
      return std::nullopt;
    }
    return value;
  } catch (const std::exception&) {
    return std::nullopt;
  }
}

auto parseByteSequence(int argc, char** argv, int& index,
                       std::vector<uint8_t>& dst, std::string_view option)
    -> bool {
  bool parsed = false;
  while (index + 1 < argc) {
    std::string_view next = argv[index + 1];
    if (next.starts_with("--")) {
      break;
    }
    ++index;
    auto value = parseUnsigned(next, 0xFF);
    if (!value.has_value()) {
      std::cerr << "Invalid value for --" << option << ": '" << next << "'\n";
      return false;
    }
    dst.push_back(static_cast<uint8_t>(*value));
    parsed = true;
  }
  if (!parsed) {
    std::cerr << "--" << option << " requires at least one byte.\n";
  }
  return parsed;
}

auto parseOptions(int argc, char** argv) -> std::optional<Options> {
  Options opts{};

  for (int i = 1; i < argc; ++i) {
    std::string_view arg = argv[i];
    if (!arg.starts_with("--")) {
      std::cerr << "Unknown argument: " << arg << "\n";
      return std::nullopt;
    }
    auto name = arg.substr(2);

    auto takeValue = [&](std::string_view opt) -> std::optional<std::string> {
      if (i + 1 >= argc) {
        std::cerr << "--" << opt << " requires a value.\n";
        return std::nullopt;
      }
      return std::string(argv[++i]);
    };

    if (name == "ip") {
      if (auto v = takeValue(name)) {
        opts.ip = std::move(*v);
      } else {
        return std::nullopt;
      }
    } else if (name == "port") {
      if (auto v = takeValue(name)) {
        opts.port = std::move(*v);
      } else {
        return std::nullopt;
      }
    } else if (name == "target-address") {
      if (!parseByteSequence(argc, argv, i, opts.target_address, name)) {
        return std::nullopt;
      }
    } else if (name == "reply-address") {
      if (!parseByteSequence(argc, argv, i, opts.reply_address, name)) {
        return std::nullopt;
      }
    } else if (name == "ntimes") {
      if (auto v = takeValue(name)) {
        auto parsed =
            parseUnsigned(*v, std::numeric_limits<std::size_t>::max());
        if (!parsed.has_value() || *parsed == 0) {
          std::cerr << "Invalid --ntimes: '" << *v << "'\n";
          return std::nullopt;
        }
        opts.ntimes = static_cast<std::size_t>(*parsed);
      } else {
        return std::nullopt;
      }
    } else if (name == "nbytes") {
      if (auto v = takeValue(name)) {
        auto parsed =
            parseUnsigned(*v, std::numeric_limits<std::size_t>::max());
        if (!parsed.has_value() || *parsed == 0 ||
            *parsed > std::numeric_limits<uint32_t>::max()) {
          std::cerr << "--nbytes must be within [1, 0xFFFFFFFF].\n";
          return std::nullopt;
        }
        opts.nbytes = static_cast<std::size_t>(*parsed);
      } else {
        return std::nullopt;
      }
    } else if (name == "start_address") {
      if (auto v = takeValue(name)) {
        auto parsed = parseUnsigned(*v, std::numeric_limits<uint32_t>::max());
        if (!parsed.has_value()) {
          std::cerr << "Invalid --start_address: '" << *v << "'\n";
          return std::nullopt;
        }
        opts.start_address = static_cast<uint32_t>(*parsed);
      } else {
        return std::nullopt;
      }
    } else if (name == "out") {
      if (auto v = takeValue(name)) {
        opts.out_path = std::move(*v);
      } else {
        return std::nullopt;
      }
    } else if (name == "help") {
      printUsage(argv[0]);
      std::exit(0);
    } else {
      std::cerr << "Unknown option: --" << name << "\n";
      return std::nullopt;
    }
  }

  if (opts.target_address.empty()) {
    std::cerr << "--target-address is required.\n";
    return std::nullopt;
  }
  if (opts.reply_address.empty()) {
    std::cerr << "--reply-address is required.\n";
    return std::nullopt;
  }
  if (!opts.ntimes.has_value()) {
    std::cerr << "--ntimes is required.\n";
    return std::nullopt;
  }
  if (!opts.nbytes.has_value()) {
    std::cerr << "--nbytes is required.\n";
    return std::nullopt;
  }
  if (!opts.start_address.has_value()) {
    std::cerr << "--start_address is required.\n";
    return std::nullopt;
  }

  return opts;
}

auto computeMean(const std::vector<double>& xs) -> double {
  if (xs.empty()) {
    return 0.0;
  }
  double sum = std::accumulate(xs.begin(), xs.end(), 0.0);
  return sum / static_cast<double>(xs.size());
}

auto computeStd(const std::vector<double>& xs, double mean) -> double {
  if (xs.size() <= 1) {
    return 0.0;
  }
  double acc = 0.0;
  for (double v : xs) {
    const double diff = v - mean;
    acc += diff * diff;
  }
  return std::sqrt(acc / static_cast<double>(xs.size()));
}

auto medianSorted(const std::vector<double>& xs) -> double {
  if (xs.empty()) {
    return 0.0;
  }
  const std::size_t n = xs.size();
  if (n % 2 == 1) {
    return xs[n / 2];
  }
  return 0.5 * (xs[n / 2 - 1] + xs[n / 2]);
}

auto computeQuartiles(std::vector<double> xs)
    -> std::tuple<double, double, double, double, double> {
  if (xs.empty()) {
    return {0.0, 0.0, 0.0, 0.0, 0.0};
  }
  std::ranges::sort(xs);
  const long n = static_cast<long>(xs.size());
  const double min_v = xs.front();
  const double max_v = xs.back();
  const double median = medianSorted(xs);

  const long mid = n / 2;
  std::vector<double> lower(xs.begin(), xs.begin() + mid);
  std::vector<double> upper;
  if (n % 2 == 0) {
    upper.assign(xs.begin() + mid, xs.end());
  } else {
    upper.assign(xs.begin() + mid + 1, xs.end());
  }
  const double q1 = lower.empty() ? min_v : medianSorted(lower);
  const double q3 = upper.empty() ? max_v : medianSorted(upper);
  return {min_v, q1, median, q3, max_v};
}

auto toMicroseconds(double value) -> long long {
  return static_cast<long long>(std::llround(value));
}

void trySetHighestPriority() {
#if defined(__linux__)
  {
    sched_param sp{};
    sp.sched_priority = sched_get_priority_max(SCHED_FIFO);

    int ret = pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);
    if (ret != 0) {
      std::cerr << "Warning: failed to set SCHED_FIFO: " << std::strerror(ret)
                << '\n';
    } else {
      std::cerr << "SCHED_FIFO with max priority is set.\n";
    }
  }

  {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);  // 必要に応じてコア番号は変更する

    int ret = pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
    if (ret != 0) {
      std::cerr << "Warning: failed to set CPU affinity: " << std::strerror(ret)
                << '\n';
    } else {
      std::cerr << "Pinned current thread to CPU 0.\n";
    }
  }

  errno = 0;
  if (setpriority(PRIO_PROCESS, 0, -20) != 0) {
    std::cerr << "Warning: failed to raise CPU priority (nice): "
              << std::strerror(errno) << '\n';
  }

#elif defined(__APPLE__)
  errno = 0;
  if (setpriority(PRIO_PROCESS, 0, -20) != 0) {
    std::cerr << "Warning: failed to raise CPU priority (nice): "
              << std::strerror(errno) << '\n';
  } else {
    std::cerr << "Nice priority raised to -20.\n";
  }
#else
  std::cerr << "Info: priority tuning is not supported on this platform.\n";
#endif
}
}  // namespace

auto main(int argc, char** argv) -> int {
  auto options = parseOptions(argc, argv);
  if (!options) {
    printUsage(argv[0]);
    return 1;
  }
  auto opts = std::move(*options);

  trySetHighestPriority();

  std::ofstream out_file;
  if (opts.out_path) {
    out_file.open(*opts.out_path, std::ios::out | std::ios::trunc);
    if (!out_file.is_open()) {
      std::cerr << "Failed to open output file: " << *opts.out_path << "\n";
      return 1;
    }
    out_file << "index,elapsed_ns\n";
  }

  const std::size_t ntimes = *opts.ntimes;
  const std::size_t total_bytes = *opts.nbytes;
  const uint32_t base_address = *opts.start_address;
  const auto range_end = static_cast<unsigned long long>(base_address) +
                         static_cast<unsigned long long>(total_bytes);
  if (range_end >
      static_cast<unsigned long long>(std::numeric_limits<uint32_t>::max()) +
          1ULL) {
    std::cerr << "--start_address + --nbytes exceeds 32-bit address space.\n";
    return 1;
  }

  std::vector<uint8_t> pattern(total_bytes);
  std::mt19937 rng(std::random_device{}());
  std::uniform_int_distribution<int> dist(0, 0xFF);
  for (auto& byte : pattern) {
    byte = static_cast<uint8_t>(dist(rng));
  }

  auto client =
      spw_rmap::SpwRmapTCPClient({.ip_address = opts.ip, .port = opts.port});
  client.setInitiatorLogicalAddress(kInitiatorLogicalAddress);
  client.setAutoPollingMode(true);

  auto connect_res = client.connect(1s);
  if (!connect_res.has_value()) {
    std::cerr << "Failed to connect: " << connect_res.error().message() << "\n";
    return 1;
  }

  auto target = spw_rmap::TargetNode(kTargetLogicalAddress)
                    .setTargetAddress(std::move(opts.target_address))
                    ->setReplyAddress(std::move(opts.reply_address))
                    .value();

  // Initial write of the pattern into the device memory.
  for (std::size_t offset = 0; offset < total_bytes; offset += kChunkSize) {
    const std::size_t chunk = std::min(kChunkSize, total_bytes - offset);
    std::span<const uint8_t> chunk_span(pattern.data() + offset, chunk);
    auto res = client.write(
        target, base_address + static_cast<uint32_t>(offset), chunk_span);
    if (!res.has_value()) {
      std::cerr << "Write failed at offset " << offset << ": "
                << res.error().message() << "\n";
      if (auto shutdown_res = client.shutdown(); !shutdown_res.has_value()) {
        std::cerr << "Shutdown error: " << shutdown_res.error().message()
                  << "\n";
      }
      return 1;
    }
  }

  std::vector<double> latencies_ns;
  latencies_ns.reserve(ntimes);
  std::vector<uint8_t> read_buffer(total_bytes);

  for (std::size_t iter = 0; iter < 20000; ++iter) {
    std::vector<uint8_t> warmup_buffer{};
    warmup_buffer.resize(4);
    auto res = client.read(target, base_address, warmup_buffer);
    if (!res.has_value()) {
      std::cerr << "Warm-up read failed during iteration " << (iter + 1) << ": "
                << res.error().message() << "\n";
      if (auto shutdown_res = client.shutdown(); !shutdown_res.has_value()) {
        std::cerr << "Shutdown error: " << shutdown_res.error().message()
                  << "\n";
      }
      return 1;
    }
  }

  for (std::size_t iter = 0; iter < ntimes; ++iter) {
    const auto start_time = Clock::now();
    auto res = client.read(target, base_address, std::span(read_buffer));
    const auto end_time = Clock::now();
    if (!res.has_value()) {
      std::cerr << "Read failed during iteration " << (iter + 1) << ": "
                << res.error().message() << "\n";
      if (auto shutdown_res = client.shutdown(); !shutdown_res.has_value()) {
        std::cerr << "Shutdown error: " << shutdown_res.error().message()
                  << "\n";
      }
      return 1;
    }

    if (!std::ranges::equal(read_buffer, pattern)) {
      std::cerr << "Data mismatch detected during iteration " << (iter + 1)
                << "\n";
      if (auto shutdown_res = client.shutdown(); !shutdown_res.has_value()) {
        std::cerr << "Shutdown error: " << shutdown_res.error().message()
                  << "\n";
      }
      return 1;
    }

    const auto elapsed =
        std::chrono::duration<double, std::nano>(end_time - start_time).count();
    latencies_ns.push_back(elapsed);
  }

  if (out_file.is_open()) {
    out_file << "index,elapsed_ns\n" << std::fixed << std::setprecision(0);
    for (std::size_t i = 0; i < latencies_ns.size(); ++i) {
      out_file << (i + 1) << ',' << latencies_ns[i] << '\n';
    }
  }

  auto mean = computeMean(latencies_ns);
  auto stddev = computeStd(latencies_ns, mean);
  auto [min_v, q1, median, q3, max_v] = computeQuartiles(latencies_ns);

  std::cout << "mean=" << toMicroseconds(mean)
            << " std=" << toMicroseconds(stddev)
            << " min=" << toMicroseconds(min_v) << " q1=" << toMicroseconds(q1)
            << " median=" << toMicroseconds(median)
            << " q3=" << toMicroseconds(q3) << " max=" << toMicroseconds(max_v)
            << '\n';

  std::cerr << "Test completed successfully with " << ntimes
            << " iterations.\n";

  auto shutdown_res = client.shutdown();
  if (!shutdown_res.has_value()) {
    std::cerr << "Shutdown error: " << shutdown_res.error().message() << "\n";
    return 1;
  }
  return 0;
}
