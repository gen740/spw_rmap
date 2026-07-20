cmake_minimum_required(VERSION 3.15)
project(spw_rmap LANGUAGES CXX)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(SPWRMAP_BUILD_APPS "Build command line applications" ON)
option(SPWRMAP_BUILD_EXAMPLES "Build examples" OFF)
option(SPWRMAP_BUILD_TESTS "Build tests" OFF)
option(SPWRMAP_BUILD_FUZZERS "Build libFuzzer targets" OFF)
option(SPWRMAP_ENABLE_DEBUG_LOGS "Enable debug logging helpers" ON)
option(SPWRMAP_ENABLE_TSAN "Enable ThreadSanitizer instrumentation" OFF)

if(SPWRMAP_ENABLE_TSAN AND SPWRMAP_BUILD_FUZZERS)
  message(
    FATAL_ERROR
      "ThreadSanitizer and libFuzzer sanitizers cannot be enabled together")
endif()

if(SPWRMAP_ENABLE_TSAN)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    message(FATAL_ERROR "SPWRMAP_ENABLE_TSAN requires Clang or GCC")
  endif()
  add_compile_options(-fsanitize=thread -fno-omit-frame-pointer)
  add_link_options(-fsanitize=thread)
endif()

if(SPWRMAP_BUILD_FUZZERS AND NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR "SPWRMAP_BUILD_FUZZERS requires Clang with libFuzzer")
endif()

add_library(${PROJECT_NAME} STATIC)
if(SPWRMAP_BUILD_FUZZERS)
  target_compile_options(
    ${PROJECT_NAME} PRIVATE -fsanitize=fuzzer-no-link,address,undefined
                            -fno-omit-frame-pointer)
endif()
if(SPWRMAP_ENABLE_DEBUG_LOGS)
  target_compile_definitions(${PROJECT_NAME} PUBLIC SPW_RMAP_DEBUG=1)
else()
  target_compile_definitions(${PROJECT_NAME} PUBLIC SPW_RMAP_DEBUG=0)
endif()

add_subdirectory(src)

if(SPWRMAP_BUILD_APPS)
  add_subdirectory(app)
endif()

if(SPWRMAP_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(SPWRMAP_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(SPWRMAP_BUILD_FUZZERS)
  add_subdirectory(fuzz)
endif()

if(SPWRMAP_BUILD_PYTHON_BINDINGS)
  add_subdirectory(bindings/python)
endif()

include(CMakePackageConfigHelpers)

install(
  TARGETS ${PROJECT_NAME}
  EXPORT spw_rmapTargets
  INCLUDES
  DESTINATION include
  ARCHIVE DESTINATION lib)

install(
  EXPORT spw_rmapTargets
  FILE spw_rmapTargets.cmake
  NAMESPACE spw_rmap::
  DESTINATION lib/cmake/spw_rmap)

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/spw_rmapConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/spw_rmapConfig.cmake
  INSTALL_DESTINATION lib/cmake/spw_rmap)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/spw_rmapConfigVersion.cmake
  VERSION 0.3.0
  COMPATIBILITY SameMajorVersion)

file(GLOB HEADER_FILES ${CMAKE_SOURCE_DIR}/include/spw_rmap/*.hh)
file(GLOB HEADER_FILES_INTERNAL
     ${CMAKE_SOURCE_DIR}/include/spw_rmap/internal/*.hh)

install(FILES ${HEADER_FILES} DESTINATION include/spw_rmap)
install(FILES ${HEADER_FILES_INTERNAL} DESTINATION include/spw_rmap/internal)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/spw_rmapConfig.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/spw_rmapConfigVersion.cmake
        DESTINATION lib/cmake/spw_rmap)
