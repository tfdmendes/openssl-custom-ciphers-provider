#!/bin/bash
set -e

# Resolve project root directory
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${ROOT_DIR}/build"

echo "========================================"
echo " Building and Running Standalone Tests"
echo "========================================"

# Create build directory if it does not exist
mkdir -p "${BUILD_DIR}"

# Configure CMake
echo "[1/3] Configuring CMake..."
cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

# Compile the project and tests
echo "[2/3] Building targets..."
cmake --build "${BUILD_DIR}" --parallel 4

# Run all tests using CTest
echo "[3/3] Running tests..."
echo "----------------------------------------"
ctest --test-dir "${BUILD_DIR}" --output-on-failure --verbose

echo "----------------------------------------"
echo "All tests finished successfully."
