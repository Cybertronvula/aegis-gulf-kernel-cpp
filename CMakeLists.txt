cmake_minimum_required(VERSION 3.20)
project(AegisGulfKernel VERSION 0.1.0 LANGUAGES CXX)

# ── C++20 required ────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Compiler flags ────────────────────────────────────────────────────────────
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  add_compile_options(
    -O3               # Maximum optimisation
    -march=native     # Enable AES-NI / AVX2 / ARMv8 Crypto Extensions
    -Wall -Wextra -Wpedantic
    -Wno-unused-parameter
  )
endif()

# ── Find OpenSSL ──────────────────────────────────────────────────────────────
find_package(OpenSSL REQUIRED)

# ── Core kernel library ───────────────────────────────────────────────────────
add_library(aegis_engine STATIC
  engine.cpp
)

target_include_directories(aegis_engine PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(aegis_engine PUBLIC
  OpenSSL::SSL
  OpenSSL::Crypto
  Threads::Threads
)

find_package(Threads REQUIRED)

# ── Benchmark binary ──────────────────────────────────────────────────────────
add_executable(aegis_benchmark
  main.cpp
)

target_link_libraries(aegis_benchmark PRIVATE
  aegis_engine
)

# ── Install ───────────────────────────────────────────────────────────────────
install(TARGETS aegis_benchmark DESTINATION bin)
install(FILES engine.hpp DESTINATION include/aegis)

# ── Print build info ──────────────────────────────────────────────────────────
message(STATUS "Aegis Gulf Kernel v${PROJECT_VERSION}")
message(STATUS "  C++ standard:  C++20")
message(STATUS "  OpenSSL:       ${OPENSSL_VERSION}")
message(STATUS "  Build type:    ${CMAKE_BUILD_TYPE}")
message(STATUS "  Compiler:      ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
