# Include path for tests
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

# Test runner executable for PRINCE cipher
add_executable(test_prince
    test_prince.c
)

target_link_libraries(test_prince PRIVATE ciphers)

# Register the test with CTest
add_test(NAME test_prince COMMAND test_prince)
