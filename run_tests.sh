#!/usr/bin/env bash
set -e

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
build_dir="$root_dir/build"

cmake -S "$root_dir" -B "$build_dir"
cmake --build "$build_dir" --parallel 4
ctest --test-dir "$build_dir" --output-on-failure