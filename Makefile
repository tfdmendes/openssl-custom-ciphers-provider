CC ?= gcc
CFLAGS ?= -Wall -Wextra -Wpedantic -O3 -std=c99
INCLUDES = -Iinclude -Itests

BUILD_DIR = build
BIN_DIR = bin

SRCS_CIPHERS = src/ciphers/prince.c
OBJS_CIPHERS = $(BUILD_DIR)/prince.c

TEST_PRINCE_BIN = $(BIN_DIR)/test_prince

.PHONY: all clean test

all: $(TEST_PRINCE_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BUILD_DIR)/prince.o: src/ciphers/prince.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(TEST_PRINCE_BIN): tests/test_prince.c $(OBJS_CIPHERS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

test: $(TEST_PRINCE_BIN)
	./$(TEST_PRINCE_BIN)

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
