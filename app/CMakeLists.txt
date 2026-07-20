add_executable(spwrmap_cli spwrmap.cc)
target_link_libraries(spwrmap_cli PRIVATE spw_rmap)
target_compile_features(spwrmap_cli PRIVATE cxx_std_23)
set_target_properties(spwrmap_cli PROPERTIES OUTPUT_NAME spwrmap)

add_executable(spwrmap_speedtest_cli spwrmap_speedtest.cc)
target_compile_options(spwrmap_speedtest_cli PRIVATE $<$<CONFIG:Release>:-O3>)
target_link_libraries(spwrmap_speedtest_cli PRIVATE spw_rmap)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  # pthread_setaffinity_np is provided through the POSIX threads link mode on
  # manylinux aarch64.  GCC does not enable that mode merely because <pthread.h>
  # was included.
  target_compile_options(spwrmap_speedtest_cli PRIVATE -pthread)
  target_link_options(spwrmap_speedtest_cli PRIVATE -pthread)
endif()
target_compile_features(spwrmap_speedtest_cli PRIVATE cxx_std_23)
set_target_properties(spwrmap_speedtest_cli PROPERTIES
                      OUTPUT_NAME spwrmap_speedtest)

install(TARGETS spwrmap_cli spwrmap_speedtest_cli RUNTIME DESTINATION bin)

if(SPWRMAP_BUILD_PYTHON_BINDINGS)
  # Copy the CLI binaries into the Python package so entry points can invoke them.
  install(
    PROGRAMS $<TARGET_FILE:spwrmap_cli> $<TARGET_FILE:spwrmap_speedtest_cli>
    DESTINATION pyspw_rmap/bin)
endif()
