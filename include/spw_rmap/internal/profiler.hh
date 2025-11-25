#pragma once

#include <array>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iostream>

namespace spw_rmap::internal {

template <std::size_t MaxEntries>
class Profiler {
 public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;
  using Duration = Clock::duration;

  static constexpr long double tick_to_ns_ =
      (static_cast<long double>(Clock::period::num) * 1'000'000'000.0L) /
      static_cast<long double>(Clock::period::den);

  static auto get() noexcept -> Profiler& {
    static Profiler instance;
    return instance;
  }

  auto clear() noexcept -> void {
    for (auto& e : entries_) {
      e = EntryStats{};
    }
    run_count_ = 0;
    active_ = false;
  }

  auto start() noexcept -> void {
    has_checkpoint_.fill(false);
    active_ = true;
    start_time_ = Clock::now();
  }

  auto end() noexcept -> void {
    if (!active_) [[unlikely]] {
      return;
    }

    for (std::size_t i = 0; i < MaxEntries; ++i) {
      if (!has_checkpoint_.at(i)) continue;
      const Duration dt = checkpoints_.at(i) - start_time_;
      const auto ticks = dt.count();
      const long double ns = static_cast<long double>(ticks) * tick_to_ns_;
      auto& e = entries_.at(i);
      if (!e.has_value) {
        e.min_ns = ns;
        e.max_ns = ns;
        e.has_value = true;
      } else {
        if (ns < e.min_ns) e.min_ns = ns;
        if (ns > e.max_ns) e.max_ns = ns;
      }

      ++e.count;
      e.sum_ns += ns;
      e.sum_sq_ns += ns * ns;
    }

    ++run_count_;
    active_ = false;
  }

  template <std::size_t index>
    requires(index < MaxEntries)
  auto check() noexcept -> void {
    checkpoints_[index] = Clock::now();
    has_checkpoint_[index] = true;
  }

  auto show(std::ostream& os = std::cout) const -> void {
    os << "==== Profiler Result ====\n";
    os << "Runs: " << run_count_ << "\n";

    for (std::size_t i = 0; i < MaxEntries; ++i) {
      const auto& e = entries_.at(i);
      if (!e.has_value || e.count == 0) {
        continue;
      }

      const auto n = static_cast<long double>(e.count);
      const long double mean = e.sum_ns / n;
      long double var = 0.0L;
      if (e.count > 1) {
        var = e.sum_sq_ns / n - mean * mean;
        if (var < 0.0L) var = 0.0L;
      }
      const long double stddev = (e.count > 1) ? std::sqrt(var) : 0.0L;

      os << "index=" << i << "\n";
      os << "  count = " << e.count << "\n";
      os << "  mean  = " << static_cast<double>(mean) << " ns\n";
      os << "  std   = " << static_cast<double>(stddev) << " ns\n";
      os << "  min   = " << static_cast<double>(e.min_ns) << " ns\n";
      os << "  max   = " << static_cast<double>(e.max_ns) << " ns\n";
    }

    os << "=========================\n";
  }

 private:
  struct EntryStats {
    std::uint64_t count{0};
    long double sum_ns{0.0L};
    long double sum_sq_ns{0.0L};
    long double min_ns{0.0L};
    long double max_ns{0.0L};
    bool has_value{false};
  };

  TimePoint start_time_{};
  std::array<TimePoint, MaxEntries> checkpoints_{};
  std::array<bool, MaxEntries> has_checkpoint_{};

  std::array<EntryStats, MaxEntries> entries_{};
  std::uint64_t run_count_{0};
  bool active_{false};

  Profiler() = default;
  ~Profiler() = default;

 public:
  Profiler(const Profiler&) = delete;
  auto operator=(const Profiler&) -> Profiler& = delete;
  Profiler(Profiler&&) = delete;
  auto operator=(Profiler&&) -> Profiler& = delete;
};

}  // namespace spw_rmap::internal
