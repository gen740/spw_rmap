cmake_minimum_required(VERSION 3.27)

find_package(GTest REQUIRED)

file(GLOB TEST_SOURCES CONFIGURE_DEPENDS *.cc)

add_executable(spwrmap_tests ${TEST_SOURCES})

target_link_libraries(spwrmap_tests PRIVATE spw_rmap GTest::gtest
                                            GTest::gtest_main)

target_compile_options(spwrmap_tests PRIVATE -Werror -Wall -Wextra -Wpedantic)
target_include_directories(spwrmap_tests PRIVATE ${CMAKE_SOURCE_DIR}/include)

include(GoogleTest)
if(SPWRMAP_ENABLE_TSAN)
  # Avoid executing the instrumented binary during the build. Some toolchains
  # can compile TSan binaries even when their host runtime cannot start them.
  gtest_add_tests(TARGET spwrmap_tests SOURCES ${TEST_SOURCES})
else()
  gtest_discover_tests(spwrmap_tests)
endif()
