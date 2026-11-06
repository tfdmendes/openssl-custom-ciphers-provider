#ifndef TEST_OUTPUT_H
#define TEST_OUTPUT_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static inline int test_output_color(void) {
    const char *no_color = getenv("NO_COLOR");
    const char *force_color = getenv("CLICOLOR_FORCE");
    const char *term = getenv("TERM");

    if (no_color != NULL && no_color[0] != '\0') return 0;
    if (force_color != NULL && force_color[0] != '\0' && strcmp(force_color, "0") != 0) return 1;
    return isatty(STDOUT_FILENO) && (term == NULL || strcmp(term, "dumb") != 0);
}

static inline void test_output_bytes(const uint8_t *data, size_t len) {
    if (len == 0) printf("(empty)");
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
}

static inline void test_output_field(const char *label, const uint8_t *data, size_t len) {
    printf("- %s: ", label);
    test_output_bytes(data, len);
    printf("\n");
}

static inline void test_output_case(size_t number, const char *name,
                                    const uint8_t *key, size_t key_len,
                                    const uint8_t *iv, size_t iv_len,
                                    const char *input_label, const uint8_t *input, size_t input_len) {
    printf("\nTest %zu (%s)\n", number, name);
    test_output_field("Key", key, key_len);
    if (iv != NULL) test_output_field("IV", iv, iv_len);
    test_output_field(input_label, input, input_len);
}

static inline int test_output_result(const uint8_t *expected, size_t expected_len,
                                     const uint8_t *result, size_t result_len) {
    int matches = result != NULL && expected_len == result_len
                  && memcmp(expected, result, expected_len) == 0;
    int color = test_output_color();

    test_output_field("Expected Result", expected, expected_len);
    printf("%s- Result: ", color ? (matches ? "\033[32m" : "\033[31m") : "");
    if (result == NULL) printf("(operation failed)");
    else test_output_bytes(result, result_len);
    printf(" [%s]%s\n", matches ? "PASS" : "FAIL", color ? "\033[0m" : "");
    return matches;
}

#endif
