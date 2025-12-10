#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include "spw_rmap/spw_rmap_tcp_node.hh"

namespace {

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

struct Options {
  std::string ip{"127.0.0.1"};
  std::string port{"10030"};
  double frequency_hz{1.0};
  uint8_t start_value{0};
};

std::atomic<bool> g_should_run{true};

void handleSignal(int /*signum*/) noexcept {
  g_should_run.store(false, std::memory_order_relaxed);
}

void installSignalHandlers() {
  std::signal(SIGINT, handleSignal);
  std::signal(SIGTERM, handleSignal);
}

void printUsage(const char* program) {
  std::cerr << "Usage: " << program
            << " [--ip <addr>] [--port <port>] --freq <hz> [--start <value>]\n"
            << "Emit SpaceWire time codes at the requested frequency until "
               "Ctrl+C is pressed.\n\n"
            << "Options:\n"
            << "  --ip <addr>      TCP bridge IP address (default 127.0.0.1)\n"
            << "  --port <port>    TCP bridge port (default 10030)\n"
            << "  --freq <hz>      Frequency in Hz (must be > 0)\n"
            << "  --start <value>  Initial 6-bit time code value (default 0)\n"
            << "  --help           Show this message\n";
}

auto parseFrequency(std::string_view token) -> std::optional<double> {
  try {
    std::string value(token);
    auto freq = std::stod(value);
    if (freq <= 0.0 || !std::isfinite(freq)) {
      return std::nullopt;
    }
    return freq;
  } catch (const std::exception&) {
    return std::nullopt;
  }
}

auto parseStartValue(std::string_view token) -> std::optional<uint8_t> {
  try {
    std::string value(token);
    size_t idx = 0;
    auto parsed = std::stoul(value, &idx, 0);
    if (idx != value.size() || parsed > 0x3F) {
      return std::nullopt;
    }
    return static_cast<uint8_t>(parsed & 0x3F);
  } catch (const std::exception&) {
    return std::nullopt;
  }
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

    auto takeValue =
        [&](std::string_view option) -> std::optional<std::string> {
      if (i + 1 >= argc) {
        std::cerr << "--" << option << " requires a value.\n";
        return std::nullopt;
      }
      return std::string(argv[++i]);
    };

    if (name == "ip") {
      if (auto value = takeValue(name)) {
        opts.ip = std::move(*value);
      } else {
        return std::nullopt;
      }
    } else if (name == "port") {
      if (auto value = takeValue(name)) {
        opts.port = std::move(*value);
      } else {
        return std::nullopt;
      }
    } else if (name == "freq") {
      if (auto value = takeValue(name)) {
        auto freq = parseFrequency(*value);
        if (!freq) {
          std::cerr << "Invalid --freq: '" << *value
                    << "' (must be positive)\n";
          return std::nullopt;
        }
        opts.frequency_hz = *freq;
      } else {
        return std::nullopt;
      }
    } else if (name == "start") {
      if (auto value = takeValue(name)) {
        auto parsed = parseStartValue(*value);
        if (!parsed) {
          std::cerr << "Invalid --start: '" << *value
                    << "' (must be in [0, 63])\n";
          return std::nullopt;
        }
        opts.start_value = *parsed;
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

  if (opts.frequency_hz <= 0.0) {
    std::cerr << "--freq must be specified and greater than zero.\n";
    return std::nullopt;
  }

  return opts;
}

}  // namespace

auto main(int argc, char** argv) -> int {
  auto options = parseOptions(argc, argv);
  if (!options) {
    printUsage(argv[0]);
    return 1;
  }
  auto opts = std::move(*options);

  installSignalHandlers();

  spw_rmap::SpwRmapTCPClient client(
      {.ip_address = opts.ip, .port = opts.port});
  client.setInitiatorLogicalAddress(0xFE);
  client.setAutoPollingMode(true);

  auto connect_res = client.connect(1s);
  if (!connect_res.has_value()) {
    std::cerr << "Failed to connect to " << opts.ip << ":" << opts.port << " - "
              << connect_res.error().message() << "\n";
    return 1;
  }

  auto interval = std::chrono::duration<double>(1.0 / opts.frequency_hz);
  auto tick = std::chrono::duration_cast<Clock::duration>(interval);
  if (tick.count() <= 0) {
    tick = Clock::duration(1);
  }

  std::cout << "Emitting time codes at " << opts.frequency_hz
            << " Hz. Press Ctrl+C to stop.\n";

  uint8_t value = opts.start_value & 0x3F;
  auto next_wakeup = Clock::now();
  while (g_should_run.load(std::memory_order_relaxed)) {
    auto emit_res = client.emitTimeCode(value);
    if (!emit_res.has_value()) {
      std::cerr << "\nFailed to emit time code " << static_cast<int>(value)
                << ": " << emit_res.error().message() << "\n";
      break;
    }
    std::cout << "\rtimecode=" << std::setw(2) << std::setfill('0')
              << static_cast<int>(value) << std::setfill(' ') << std::flush;
    value = static_cast<uint8_t>((value + 1) & 0x3F);
    next_wakeup += tick;
    std::this_thread::sleep_until(next_wakeup);
  }
  std::cout << "\nStopping timecode emission.\n";

  auto shutdown_res = client.shutdown();
  if (!shutdown_res.has_value()) {
    std::cerr << "Shutdown error: " << shutdown_res.error().message() << "\n";
    return 1;
  }

  return 0;
}
