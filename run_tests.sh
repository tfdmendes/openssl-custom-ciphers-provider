#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
build_dir="$root_dir/build"

cmake_args=(-DCMAKE_BUILD_TYPE=Release)

# Use Homebrew OpenSSL 3 for both the provider and CLI tests on macOS
if [ "$(uname -s)" = Darwin ]; then
    openssl_prefix="$(brew --prefix openssl@3)"
    export PATH="$openssl_prefix/bin:$PATH"
    cmake_args+=(
        -DOPENSSL_ROOT_DIR="$openssl_prefix"
        -DOPENSSL_INCLUDE_DIR="$openssl_prefix/include"
        -DOPENSSL_CRYPTO_LIBRARY="$openssl_prefix/lib/libcrypto.dylib"
        -DOPENSSL_SSL_LIBRARY="$openssl_prefix/lib/libssl.dylib"
    )
fi

cmake -S "$root_dir" -B "$build_dir" "${cmake_args[@]}"
cmake --build "$build_dir" --parallel 4
ctest --test-dir "$build_dir" --output-on-failure
