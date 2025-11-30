#include "spw_rmap/error_code.hh"

namespace spw_rmap {

auto status_code_category() noexcept -> const std::error_category& {
  static RMAPStatusCodeCategory instance;
  return instance;
}

}  // namespace spw_rmap
