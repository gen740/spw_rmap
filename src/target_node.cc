// Copyright (c) 2025 Gen
// Licensed under the MIT License. See LICENSE file for details.
#include "spw_rmap/target_node.hh"

#include <exception>
#include <iostream>

namespace spw_rmap::detail {

void FailAddressTooLong(const char* what, std::size_t actual, std::size_t max) {
  std::cerr << "spw_rmap fatal: " << what << " length " << actual
            << " exceeds maximum " << max << "; aborting" << std::endl;
  std::terminate();
}

}  // namespace spw_rmap::detail
