#include "spw_rmap/internal/debug.hh"

#if SPW_RMAP_DEBUG
namespace spw_rmap::debug::detail {

auto runtime_flag() noexcept -> std::atomic<bool>& {
  static std::atomic<bool> flag{true};
  return flag;
}

}  // namespace spw_rmap::debug::detail
#endif
