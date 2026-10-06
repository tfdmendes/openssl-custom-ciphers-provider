include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

# Test runner for PRINCE cipher KATs
add_executable(test_prince test_prince.c)
target_link_libraries(test_prince PRIVATE ciphers)
add_test(NAME test_prince COMMAND test_prince)

# Test runner for Modes & Padding
add_executable(test_modes test_modes.c)
target_link_libraries(test_modes PRIVATE ciphers)
add_test(NAME test_modes COMMAND test_modes)
