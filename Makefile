CC ?= gcc
CFLAGS ?= -Wall -Wextra -Wpedantic -O3 -std=c99
INCLUDES = -Iinclude -Itests

ifeq ($(shell uname -s),Darwin)
OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3)
OPENSSL_CFLAGS ?= -I$(OPENSSL_PREFIX)/include
OPENSSL_LIBS ?= -L$(OPENSSL_PREFIX)/lib -lcrypto
else
OPENSSL_CFLAGS ?=
OPENSSL_LIBS ?= -lcrypto
endif

BUILD_DIR = build
BIN_DIR = bin

TEST_PRINCE_BIN = $(BIN_DIR)/test_prince
TEST_RABBIT_BIN = $(BIN_DIR)/test_rabbit
TEST_MODES_BIN = $(BIN_DIR)/test_modes

.PHONY: all clean test

all: $(TEST_PRINCE_BIN) $(TEST_RABBIT_BIN) $(TEST_MODES_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BUILD_DIR)/%.o: src/ciphers/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BUILD_DIR)/%.o: src/modes/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(TEST_PRINCE_BIN): tests/test_prince.c $(BUILD_DIR)/prince.o | $(BIN_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

$(TEST_RABBIT_BIN): tests/test_rabbit.c $(BUILD_DIR)/rabbit.o | $(BIN_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

$(TEST_MODES_BIN): tests/test_modes.c $(BUILD_DIR)/prince.o $(BUILD_DIR)/modes.o $(BUILD_DIR)/padding.o | $(BIN_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) $(OPENSSL_CFLAGS) $^ -o $@ $(OPENSSL_LIBS)

test: $(TEST_PRINCE_BIN) $(TEST_RABBIT_BIN) $(TEST_MODES_BIN)
	./$(TEST_PRINCE_BIN)
	./$(TEST_RABBIT_BIN)
	./$(TEST_MODES_BIN)

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
