#!/usr/bin/env bash
# Benchmark of the custom ciphers against OpenSSL's own, through `openssl speed -evp`.
# Usage: bench/run_bench.sh [provider dir (default: build)] [seconds (default: 3)]
# Writes a Markdown table to stdout and the environment to stderr.
set -eu

PROV_DIR=${1:-build}
SECS=${2:-3}
OPT=(-provider-path "$PROV_DIR" -provider default -provider customprov)
CUSTOM=(PRINCE-ECB PRINCE-CBC PRINCE-CTR RABBIT)
BUILTIN=(AES-128-ECB AES-128-CBC AES-128-CTR ChaCha20)

{
    echo "# Environment"
    openssl version
    echo "gcc: $(gcc --version | head -1)"
    echo "cmake build type: ${CMAKE_BUILD_TYPE:-<none>}; flags from CMakeLists.txt: -O3"
    echo "kernel: $(uname -srm)"
    lscpu | grep -E 'Model name|^CPU\(s\)|Flags' | sed -E 's/(Flags:).*(aes).*/\1 ... aes ... (AES-NI present)/;/Flags:/!b' | head -4
    lscpu | grep -qw aes && echo "AES-NI: yes" || echo "AES-NI: no"
    echo "seconds per measurement: $SECS"
} >&2

echo "| Cipher | Provider | 16 B | 64 B | 256 B | 1024 B | 8192 B | 16384 B |"
echo "|---|---|---:|---:|---:|---:|---:|---:|"

run() { # run <algorithm> <provider label>
    local line
    line=$(openssl speed "${OPT[@]}" -seconds "$SECS" -evp "$1" 2>/dev/null | grep -E "^$1 " || true)
    [ -n "$line" ] || { echo "no result for $1" >&2; return; }
    # fields: name then six figures such as 19050.74k (thousands of bytes per second)
    echo "$line" | awk -v p="$2" '{printf "| %s | %s |", $1, p; for (i = 2; i <= 7; i++) printf " %.1f MB/s |", $i/1000; print ""}'
}

for a in "${CUSTOM[@]}"; do run "$a" customprov; done
for a in "${BUILTIN[@]}"; do run "$a" default; done
