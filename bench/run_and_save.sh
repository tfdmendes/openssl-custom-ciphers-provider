#!/usr/bin/env bash
# Run the benchmarks and save the results on macOS
# Usage: bash bench/run_and_save.sh [seconds per measurement]
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
seconds=${1:-3}

if ! [[ "$seconds" =~ ^[1-9][0-9]*$ ]]; then
    echo "Seconds per measurement must be a positive integer" >&2
    exit 1
fi

# Check Python before spending time running the benchmarks
if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' \
    >/dev/null 2>&1; then
    echo "Python 3.9 or newer is required to generate comparisons" >&2
    exit 1
fi

openssl_prefix="$(brew --prefix openssl@3)"
export PATH="$openssl_prefix/bin:$PATH"

build_dir="$root_dir/build"

# Build and test first so we only benchmark a working provider
bash "$root_dir/run_tests.sh"

# Create a separate folder for each run so we keep the previous results
mkdir -p "$build_dir/benchmarks"
results_dir="$(mktemp -d "$build_dir/benchmarks/$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")"

printf 'Running benchmarks with %s seconds per measurement...\n' "$seconds"

# Save the speed table separately from machine details and errors
if ! bash "$root_dir/bench/run_bench.sh" "$build_dir" "$seconds" \
    > "$results_dir/results.md" \
    2> "$results_dir/environment.log"; then
    printf 'Benchmark failed. See %s/environment.log\n' "$results_dir" >&2
    exit 1
fi

# Compare the speeds once all benchmarks finish successfully
python3 "$root_dir/bench/compare_results.py" "$results_dir/results.md" \
    > "$results_dir/comparison.md"

printf 'Results: %s\nComparison: %s\nEnvironment: %s\n' \
    "$results_dir/results.md" \
    "$results_dir/comparison.md" \
    "$results_dir/environment.log"
