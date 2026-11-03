#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
build_dir="$root_dir/build"
results_file="$build_dir/results.md"
comparison_file="$build_dir/comparison.md"
environment_log="$build_dir/environment.log"

usage() {
    printf 'Usage: bash %s [all | build check benchmark report] [--seconds N]\n' "$0"
    printf '\nStages (run in this order, regardless of argument order):\n'
    printf '  build      Compile the provider and C test programs.\n'
    printf '  check      Run all five cipher and OpenSSL test suites using the existing build.\n'
    printf '  benchmark  Measure fresh encryption performance and save both tables and the log.\n'
    printf '  report     Display the saved tables and their measurement timestamp.\n'
    printf '  all        Run every stage (also the default when no stages are given).\n'
    printf '\nOptions:\n'
    printf '  --seconds N  Positive integer seconds per cipher and input size (default: 3).\n'
    printf '               Requires the benchmark stage; 8 ciphers x 6 sizes x N seconds.\n'
    printf '  --help       Show this help.\n'
    printf '\nSelect one or more stages. Repeated stages run once.\n'
    printf 'check and benchmark require a compiled build; include build to compile first.\n'
    printf 'Only benchmark replaces saved results. report alone makes no new measurements.\n'
    printf '\nExamples (from the repository root):\n'
    printf '  bash run_tests.sh\n'
    printf '    Run all stages with the default 3 seconds per measurement (about 144 seconds of benchmarks).\n'
    printf '  bash run_tests.sh build\n'
    printf '    Compile only.\n'
    printf '  bash run_tests.sh check\n'
    printf '    Run the five test suites using the existing build.\n'
    printf '  bash run_tests.sh build check\n'
    printf '    Compile first, then run the test suites.\n'
    printf '  bash run_tests.sh benchmark report --seconds 1\n'
    printf '    Measure fresh performance using the existing build, then display the tables (about 48 seconds).\n'
    printf '  bash run_tests.sh all --seconds 2\n'
    printf '    Run all stages with 2 seconds per measurement (about 96 seconds of benchmarks).\n'
    printf '  bash run_tests.sh report\n'
    printf '    Display saved tables and their timestamp without changing the results.\n'
}

argument_error() {
    printf '%s\n\n' "$1" >&2
    usage >&2
    exit 2
}

do_build=0
do_check=0
do_benchmark=0
do_report=0
all_selected=0
seconds=3
seconds_set=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        build) do_build=1 ;;
        check) do_check=1 ;;
        benchmark) do_benchmark=1 ;;
        report) do_report=1 ;;
        all) all_selected=1 ;;
        --seconds)
            [ "$seconds_set" -eq 0 ] || argument_error 'Use --seconds only once.'
            [ "$#" -ge 2 ] || argument_error '--seconds requires a positive integer.'
            seconds="$2"
            [[ "$seconds" =~ ^[1-9][0-9]*$ ]] || argument_error '--seconds requires a positive integer.'
            seconds_set=1
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *) argument_error "Unknown argument: $1" ;;
    esac
    shift
done

selected_count=$((do_build + do_check + do_benchmark + do_report))
if [ "$all_selected" -eq 1 ] && [ "$selected_count" -ne 0 ]; then
    argument_error 'Use all on its own, or list the individual stages.'
fi
if [ "$selected_count" -eq 0 ]; then
    do_build=1
    do_check=1
    do_benchmark=1
    do_report=1
fi
if [ "$seconds_set" -eq 1 ] && [ "$do_benchmark" -eq 0 ]; then
    argument_error '--seconds requires the benchmark stage.'
fi

stages=()
[ "$do_build" -eq 0 ] || stages+=(build)
[ "$do_check" -eq 0 ] || stages+=(check)
[ "$do_benchmark" -eq 0 ] || stages+=(benchmark)
[ "$do_report" -eq 0 ] || stages+=(report)

cmake_args=(-DCMAKE_BUILD_TYPE=Release)
provider_file="$build_dir/customprov.so"

# Use the same OpenSSL 3 installation for compilation, checks, and measurements
if [ "$do_build" -eq 1 ] || [ "$do_check" -eq 1 ] || [ "$do_benchmark" -eq 1 ]; then
    if [ "$(uname -s)" = Darwin ]; then
        if ! command -v brew >/dev/null 2>&1; then
            printf 'Homebrew with openssl@3 is required on macOS.\n' >&2
            exit 1
        fi
        openssl_prefix="$(brew --prefix openssl@3)"
        if [ ! -x "$openssl_prefix/bin/openssl" ] || [ ! -f "$openssl_prefix/lib/libcrypto.dylib" ]; then
            printf 'OpenSSL 3 is missing. Install it with: brew install openssl@3\n' >&2
            exit 1
        fi
        export PATH="$openssl_prefix/bin:$PATH"
        cmake_args+=(
            -DOPENSSL_ROOT_DIR="$openssl_prefix"
            -DOPENSSL_INCLUDE_DIR="$openssl_prefix/include"
            -DOPENSSL_CRYPTO_LIBRARY="$openssl_prefix/lib/libcrypto.dylib"
            -DOPENSSL_SSL_LIBRARY="$openssl_prefix/lib/libssl.dylib"
        )
        provider_file="$build_dir/customprov.dylib"
    fi
    if ! command -v openssl >/dev/null 2>&1; then
        printf 'OpenSSL 3.x is required on PATH.\n' >&2
        exit 1
    fi
    openssl_version="$(openssl version)"
    if [[ "$openssl_version" != "OpenSSL 3."* ]]; then
        printf 'OpenSSL 3.x is required; found: %s\n' "$openssl_version" >&2
        exit 1
    fi
fi

dependencies=()
[ "$do_build" -eq 0 ] || dependencies+=(cmake)
[ "$do_check" -eq 0 ] || dependencies+=(ctest awk cmp xxd)
[ "$do_benchmark" -eq 0 ] || dependencies+=(awk mktemp)
[ "$do_report" -eq 0 ] || dependencies+=(awk)
for dependency in "${dependencies[@]}"; do
    if ! command -v "$dependency" >/dev/null 2>&1; then
        printf 'Required command not found: %s\n' "$dependency" >&2
        exit 1
    fi
done

require_build() {
    if [ ! -f "$provider_file" ] || [ ! -f "$build_dir/CMakeCache.txt" ]; then
        printf 'Compiled provider not found in %s. Run the build stage first.\n' "$build_dir" >&2
        printf 'Example: bash %s build check benchmark report\n' "$0" >&2
        exit 1
    fi
}

build_provider() {
    mkdir -p "$build_dir"
    if cmake -S "$root_dir" -B "$build_dir" "${cmake_args[@]}" > "$build_dir/build.log" 2>&1 &&
        cmake --build "$build_dir" --parallel 4 >> "$build_dir/build.log" 2>&1; then
        printf 'Build OK\n'
    else
        printf 'Build failed (build/build.log):\n' >&2
        cat "$build_dir/build.log" >&2
        return 1
    fi
}

check_results() {
    require_build
    for test_name in test_prince test_rabbit test_modes test_provider; do
        if [ ! -x "$build_dir/tests/$test_name" ]; then
            printf 'Missing test executable: %s/tests/%s. Run the build stage first.\n' "$build_dir" "$test_name" >&2
            exit 1
        fi
    done
    if [ ! -f "$build_dir/CTestTestfile.cmake" ] || [ ! -f "$build_dir/tests/CTestTestfile.cmake" ]; then
        printf 'CTest registration files are missing. Run the build stage first.\n' >&2
        exit 1
    fi
    registration="$(cd "$build_dir" && ctest --show-only)"
    for test_name in test_prince test_rabbit test_modes test_provider roundtrip; do
        if ! printf '%s\n' "$registration" | awk -v name="$test_name" '
            $1 == "Test" && $NF == name { found = 1 }
            END { if (!found) exit 1 }
        '; then
            printf 'Required CTest suite is not registered: %s. Run the build stage first.\n' "$test_name" >&2
            exit 1
        fi
    done
    (
        cd "$build_dir"
        ctest --output-on-failure
    )
}

measure_performance() {
    require_build
    work_dir="$(mktemp -d "$build_dir/.run-tests.XXXXXX")"
    trap 'rm -rf "$work_dir"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    # Remove previous tables so a failed measurement cannot look like a new result
    rm -f "$results_file" "$comparison_file"
    : > "$environment_log"
    algorithms=(PRINCE-ECB PRINCE-CBC PRINCE-CTR RABBIT AES-128-ECB AES-128-CBC AES-128-CTR ChaCha20)
    providers=(customprov customprov customprov customprov default default default default)
    provider_args=(-provider-path "$build_dir" -provider default -provider customprov)
    started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    printf '8 ciphers x 6 sizes x %s s (~%s s total)\n' "$seconds" "$((48 * seconds))"

    {
        printf 'Benchmark started (UTC): %s\n' "$started_at"
        printf 'System: %s\n' "$(uname -srm)"
        printf 'Operation: encryption using openssl speed -evp\n'
        printf 'Timing: elapsed wall-clock time (-elapsed), %s seconds per input size\n' "$seconds"
        printf 'Input sizes in bytes: 16 64 256 1024 8192 16384\n'
        printf 'Units: 1 MB/s = 1,000,000 bytes/s = 8 Mb/s\n'
        awk -F= '/^CMAKE_BUILD_TYPE:/ { print "Build type: " $2 }' "$build_dir/CMakeCache.txt"
        openssl version -a
        for variable in OPENSSL_CONF OPENSSL_CONF_INCLUDE OPENSSL_MODULES OPENSSL_armcap OPENSSL_ia32cap; do
            if value=$(printenv "$variable"); then
                printf '%s=%s\n' "$variable" "$value"
            else
                printf '%s=unset\n' "$variable"
            fi
        done
        case "$(uname -s)" in
            Darwin)
                printf 'CPU: %s\n' "$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unavailable)"
                ;;
            Linux)
                if command -v lscpu >/dev/null 2>&1; then
                    lscpu | awk '/^Model name:|^CPU\(s\):|^Architecture:/'
                fi
                ;;
        esac
    } >> "$environment_log"

    for index in "${!algorithms[@]}"; do
        algorithm="${algorithms[$index]}"
        provider="${providers[$index]}"
        printf '  [%s/8] %s\n' "$((index + 1))" "$algorithm"
        printf '\n--- %s (%s) ---\n' "$algorithm" "$provider" >> "$environment_log"
        if output=$(openssl speed "${provider_args[@]}" -propquery "provider=$provider" \
            -elapsed -seconds "$seconds" -mr -evp "$algorithm" 2>&1); then
            status=0
        else
            status=$?
        fi
        printf '%s\n' "$output" >> "$environment_log"
        if [ "$status" -ne 0 ]; then
            printf 'Benchmark failed for %s. See %s\n' "$algorithm" "$environment_log" >&2
            exit 1
        fi

        # OpenSSL reports bytes per second; keep those values until the final tables
        if ! printf '%s\n' "$output" | awk -F: -v algorithm="$algorithm" -v provider="$provider" '
            $1 == "+H" {
                headers++
                if ($0 != "+H:16:64:256:1024:8192:16384") invalid = 1
            }
            $1 == "+F" {
                rows++
                if (NF != 9 || $3 != algorithm) invalid = 1
                for (col = 4; col <= 9; col++) {
                    if ($col !~ /^[0-9]+([.][0-9]+)?$/ || $col + 0 <= 0) invalid = 1
                    values[col] = $col
                }
            }
            END {
                if (invalid || headers != 1 || rows != 1) exit 1
                printf "%s\t%s", algorithm, provider
                for (col = 4; col <= 9; col++) printf "\t%s", values[col]
                printf "\n"
            }
        ' >> "$work_dir/rates.tsv"; then
            printf 'Invalid benchmark output for %s. See %s\n' "$algorithm" "$environment_log" >&2
            exit 1
        fi
    done

    awk -F '\t' -v measured_at="$started_at" -v seconds="$seconds" '
        BEGIN {
            print "# Encryption throughput"
            print ""
            print "Measured in this run (UTC): " measured_at
            print "Timing: elapsed wall-clock time; " seconds " seconds per cipher and input size."
            print "Units: MB/s (megabytes per second). 1 MB/s = 1,000,000 bytes/s = 8 Mb/s."
            print ""
            print "| Cipher | Provider | 16 B | 64 B | 256 B | 1024 B | 8192 B | 16384 B |"
            print "|---|---|---:|---:|---:|---:|---:|---:|"
        }
        {
            printf "| %s | %s |", $1, $2
            for (col = 3; col <= 8; col++) printf " %.2f MB/s |", $col / 1000000
            printf "\n"
        }
    ' "$work_dir/rates.tsv" > "$work_dir/results.md"

    awk -F '\t' '
        { for (col = 3; col <= 8; col++) rates[$1, col] = $col }
        END {
            pairs = split("PRINCE-ECB PRINCE-CBC PRINCE-CTR RABBIT RABBIT", custom, " ")
            split("AES-128-ECB AES-128-CBC AES-128-CTR ChaCha20 AES-128-CTR", baseline, " ")
            print "# Relative encryption throughput"
            print ""
            print "Custom throughput / baseline throughput x 100, using unrounded measurements from this run."
            print "100% = equal speed; 50% = half; 200% = twice."
            print ""
            print "| Cipher | Baseline | 16 B | 64 B | 256 B | 1024 B | 8192 B | 16384 B |"
            print "|---|---|---:|---:|---:|---:|---:|---:|"
            for (row = 1; row <= pairs; row++) {
                printf "| %s | %s |", custom[row], baseline[row]
                for (col = 3; col <= 8; col++) printf " %.2f%% |", 100 * rates[custom[row], col] / rates[baseline[row], col]
                printf "\n"
            }
        }
    ' "$work_dir/rates.tsv" > "$work_dir/comparison.md"

    mv "$work_dir/results.md" "$results_file"
    mv "$work_dir/comparison.md" "$comparison_file"
    printf '\nBenchmark completed (UTC): %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$environment_log"
}

print_table() {
    awk -F '|' '
    function border(    col, pos) {
        printf "+"
        for (col = 1; col <= columns; col++) {
            for (pos = 0; pos < widths[col] + 2; pos++) printf "-"
            printf "+"
        }
        printf "\n"
    }
    /^[[:space:]]*\|/ {
        if ($0 ~ /^[[:space:]|:-]+$/) next
        rows++
        if (NF - 2 > columns) columns = NF - 2
        for (col = 2; col < NF; col++) {
            value = $col
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            sub(/[[:space:]]+MB\/s$/, "", value)
            cells[rows, col - 1] = value
            if (length(value) > widths[col - 1]) widths[col - 1] = length(value)
        }
    }
    END {
        if (!rows) {
            print "No Markdown table found in the results file."
            exit 1
        }
        border()
        for (row = 1; row <= rows; row++) {
            printf "|"
            for (col = 1; col <= columns; col++) {
                if (row == 1 || col <= 2) printf " %-*s |", widths[col], cells[row, col]
                else printf " %*s |", widths[col], cells[row, col]
            }
            printf "\n"
            if (row == 1) border()
        }
        border()
    }
    ' "$1"
}

display_report() {
    for table in "$results_file" "$comparison_file"; do
        if [ ! -f "$table" ]; then
            printf 'Saved benchmark table not found: %s\n' "$table" >&2
            printf 'Generate both tables with: bash %s benchmark report\n' "$0" >&2
            printf 'Include build first if the provider has not been compiled.\n' >&2
            exit 1
        fi
    done
    if [ "$do_benchmark" -eq 1 ]; then
        printf 'Source: current run\n'
    else
        printf 'Source: saved results\n'
    fi
    awk '/^Measured in this run \(UTC\):/ {
        sub(/^Measured in this run/, "Measured")
        print
    }' "$results_file"
    printf '\nThroughput: MB/s (megabytes per second)\n\n'
    print_table "$results_file"
    printf '\nRelative throughput: 100%% = baseline\n\n'
    print_table "$comparison_file"
}

printf '\nStages:'
printf ' %s' "${stages[@]}"
printf '\n'
if [ "$do_build" -eq 0 ] && { [ "$do_check" -eq 1 ] || [ "$do_benchmark" -eq 1 ]; }; then
    printf 'Build: existing binaries\n'
fi

stage_separator="$(printf '%120s' '')"
stage_separator="${stage_separator// /-}"
stage_number=0
for stage in "${stages[@]}"; do
    stage_number=$((stage_number + 1))
    printf '\n%s\n' "$stage_separator"
    case "$stage" in
        build)
            printf '\n[%s/%s] BUILD\n\n' "$stage_number" "${#stages[@]}"
            build_provider
            ;;
        check)
            printf '\n[%s/%s] CHECK: encryption/decryption\n\n' "$stage_number" "${#stages[@]}"
            check_results
            ;;
        benchmark)
            printf '\n[%s/%s] BENCHMARK: encryption speed\n\n' "$stage_number" "${#stages[@]}"
            measure_performance
            ;;
        report)
            printf '\n[%s/%s] REPORT\n\n' "$stage_number" "${#stages[@]}"
            display_report
            ;;
    esac
done
printf '\nDone.\n'
if [ "$do_benchmark" -eq 1 ] || [ "$do_report" -eq 1 ]; then
    printf '\nBenchmark results:\n'
    printf '  Throughput: %s\n' "$results_file"
    printf '  Comparison: %s\n' "$comparison_file"
    if [ -f "$environment_log" ]; then
        printf '  Environment and raw measurements: %s\n' "$environment_log"
    fi
fi
