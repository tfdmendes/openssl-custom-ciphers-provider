#!/usr/bin/env bash
# Usage: bench/run_bench.sh [provider directory] [seconds per measurement]
set -euo pipefail
export LC_ALL=C

# Use the same OpenSSL installation as the macOS build script
if [ "$(uname -s)" = Darwin ]; then
    openssl_prefix="$(brew --prefix openssl@3)"
    export PATH="$openssl_prefix/bin:$PATH"
fi

openssl_version="$(openssl version)"
if [[ "$openssl_version" != "OpenSSL 3."* ]]; then
    echo "OpenSSL 3.x is required to run these benchmarks" >&2
    exit 1
fi

provider_dir=${1:-build}
seconds=${2:-3}
provider_args=(-provider-path "$provider_dir" -provider default -provider customprov)
custom_ciphers=(PRINCE-ECB PRINCE-CBC PRINCE-CTR RABBIT)
builtin_ciphers=(AES-128-ECB AES-128-CBC AES-128-CTR ChaCha20)

if ! [[ "$seconds" =~ ^[1-9][0-9]*$ ]]; then
    echo "Seconds per measurement must be a positive integer" >&2
    exit 1
fi

# Keep environment details separate so stdout can be saved as a Markdown table
{
    echo "$openssl_version"
    echo "System: $(uname -srm)"
    echo "Seconds per measurement: $seconds"
    echo "OpenSSL build and runtime configuration:"
    openssl version -a
    for variable in OPENSSL_CONF OPENSSL_CONF_INCLUDE OPENSSL_MODULES OPENSSL_armcap OPENSSL_ia32cap; do
        if value=$(printenv "$variable"); then
            printf '%s=%s\n' "$variable" "$value"
        else
            printf '%s=unset\n' "$variable"
        fi
    done

    if [ -f "$provider_dir/CMakeCache.txt" ]; then
        awk -F= '/^CMAKE_BUILD_TYPE:/ {
            print "Build type: " ($2 == "" ? "unspecified" : $2)
        }' "$provider_dir/CMakeCache.txt"
    fi

    if [ -f "$provider_dir/compile_commands.json" ]; then
        awk '/"command":/ {
            sub(/^[[:space:]]*"command": "/, "")
            sub(/",?$/, "")
            print "Configured compile command: " $0
            exit
        }' "$provider_dir/compile_commands.json"
    fi

    case "$(uname -s)" in
        Darwin)
            echo "CPU: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unavailable)"
            echo "Logical CPUs: $(sysctl -n hw.logicalcpu 2>/dev/null || echo unavailable)"
            ;;
        Linux)
            if command -v lscpu >/dev/null 2>&1; then
                lscpu | awk '/^Model name:|^CPU\(s\):|^Architecture:/'
            else
                echo "CPU information unavailable"
            fi
            ;;
        *)
            echo "CPU information unavailable"
            ;;
    esac
} >&2

echo "| Cipher | Provider | 16 B | 64 B | 256 B | 1024 B | 8192 B | 16384 B |"
echo "|---|---|---:|---:|---:|---:|---:|---:|"

run_benchmark() {
    local algorithm=$1
    local provider=$2
    local result

    if ! result=$(openssl speed "${provider_args[@]}" -propquery "provider=$provider" \
        -seconds "$seconds" -mr -evp "$algorithm" 2>&1); then
        printf 'Benchmark failed for %s\n%s\n' "$algorithm" "$result" >&2
        return 1
    fi

    # Machine-readable +F rows contain the algorithm and rates in bytes per second
    if ! printf '%s\n' "$result" | awk -F: -v algorithm="$algorithm" -v provider="$provider" '
        $1 == "+F" && $3 == algorithm && NF == 9 {
            printf "| %s | %s |", algorithm, provider
            for (i = 4; i <= 9; i++)
                printf " %.1f MB/s |", $i / 1000000
            print ""
            found = 1
        }
        END { if (!found) exit 1 }
    '; then
        printf 'Cannot read benchmark results for %s\n%s\n' "$algorithm" "$result" >&2
        return 1
    fi
}

for algorithm in "${custom_ciphers[@]}"; do
    run_benchmark "$algorithm" customprov
done

for algorithm in "${builtin_ciphers[@]}"; do
    run_benchmark "$algorithm" default
done
