cmake_minimum_required(VERSION 3.16)
project(custom_openssl_provider C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic -O3")
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Standalone ciphers static library (pure crypto, no OpennSSL dependency)
add_library(ciphers STATIC
    src/ciphers/prince.c
)

# Standalone unit & Known Answer Tests
add_subdirectory(tests)
