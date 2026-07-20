add_executable(parse_rmap_packet_fuzz parse_rmap_packet_fuzz.cc)

target_link_libraries(parse_rmap_packet_fuzz PRIVATE spw_rmap)
target_compile_options(
  parse_rmap_packet_fuzz
  PRIVATE -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer
          -Wall -Wextra -Wpedantic)
target_link_options(parse_rmap_packet_fuzz PRIVATE
                    -fsanitize=fuzzer,address,undefined)
