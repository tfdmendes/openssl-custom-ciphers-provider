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

# Linked into the provider (a shared object), so it must be position independent
set_target_properties(ciphers PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(ciphers PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# The OpenSSL provider: a shared library (.so) that openssl loads at runtime
find_package(OpenSSL 3.0 REQUIRED)

# Keep the provider on OpenSSL 3 even when newer versions are installed
if(NOT OPENSSL_VERSION VERSION_LESS "4.0")
    message(FATAL_ERROR "OpenSSL 3.x is required. Set OPENSSL_ROOT_DIR to your OpenSSL 3 installation.")
endif()

add_library(customprov MODULE
    src/provider/provider.c
    src/provider/prince_cipher.c
    src/provider/rabbit_cipher.c
)

# No "lib" prefix: openssl looks for customprov.so, not libcustomprov.so
set_target_properties(customprov PROPERTIES PREFIX "")

if(APPLE)
    set_target_properties(customprov PROPERTIES SUFFIX ".dylib")
endif()

target_link_libraries(customprov PRIVATE ciphers OpenSSL::Crypto)

# Standalone unit & Known Answer Tests
add_subdirectory(tests)
