cmake_minimum_required(VERSION 3.16)
project(custom_openssl_provider C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic -O3")

# Enable CTest at root level
enable_testing()

# Standalone ciphers static library
add_library(ciphers STATIC
    src/ciphers/prince.c
    src/ciphers/rabbit.c
    src/modes/modes.c
    src/modes/padding.c
)

target_include_directories(ciphers PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Standalone unit & Known Answer Tests
add_subdirectory(tests)
