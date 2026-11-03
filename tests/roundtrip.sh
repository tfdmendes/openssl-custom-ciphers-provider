#!/usr/bin/env bash
set -euo pipefail

provider_dir=${1:?Usage: roundtrip.sh <provider directory>}
provider_args=(-provider-path "$provider_dir" -provider default -provider customprov)
key=00112233445566778899aabbccddeeff
iv=0102030405060708
zero_key=00000000000000000000000000000000
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
failed=0


# If command fails, record failure and continue testing
check() {
    local description=$1
    shift

    if "$@"; then
        echo "ok   $description"
    else
        echo "FAIL $description"
        failed=1
    fi
}

# Whenever the command must fail, hide its output
expect_failure() {
    local description=$1
    shift

    if "$@" >/dev/null 2>&1; then
        echo "FAIL $description (expected an error)"
        failed=1
    else
        echo "ok   $description"
    fi
}

# Receiveds the algorithm, file size and any additional OpenSSL arguments (ie, -iv)
# roundtrip <algorithm> <size> [extra enc args...]
roundtrip() {
    local algorithm=$1
    local size=$2
    shift 2

    # Stop this particular round trip if a step fails, allow check to report it 
    if [ "$size" -eq 0 ]; then
        printf '' > "$work_dir/plain" || return 1
    else
        head -c "$size" /dev/urandom > "$work_dir/plain" || return 1
    fi

    openssl enc "${provider_args[@]}" "-$algorithm" -K "$key" "$@" \
        -in "$work_dir/plain" -out "$work_dir/encrypted" || return 1
    openssl enc -d "${provider_args[@]}" "-$algorithm" -K "$key" "$@" \
        -in "$work_dir/encrypted" -out "$work_dir/decrypted" || return 1
    cmp "$work_dir/plain" "$work_dir/decrypted"
}


ciphertext_size() {
    local algorithm=$1
    local size=$2
    shift 2

    head -c "$size" /dev/zero |
        openssl enc "${provider_args[@]}" "-$algorithm" -K "$key" "$@" |
        wc -c |
        tr -d '[:space:]'
}


# Round trips around block boundaries and up to 20 MB
for mode in ECB CBC CTR OFB CFB; do
    for size in 0 1 7 8 9 16 17 1000 1000000 20000000; do
        if [ "$mode" = ECB ]; then
            check "PRINCE-$mode round-trip, $size bytes" \
                roundtrip "PRINCE-$mode" "$size"
        else
            check "PRINCE-$mode round-trip, $size bytes" \
                roundtrip "PRINCE-$mode" "$size" -iv "$iv"
        fi
    done
done

for size in 0 1 15 16 17 1000 1000000 20000000; do
    check "RABBIT round-trip, $size bytes" \
        roundtrip RABBIT "$size" -iv "$iv"
done


# Padding adds a full block to aligned input; stream modes preserve the size
check "PRINCE-CBC -nopad round-trip, 64 bytes" \
    roundtrip PRINCE-CBC 64 -iv "$iv" -nopad
check "ECB: 8 bytes -> 16" \
    test "$(ciphertext_size PRINCE-ECB 8)" -eq 16
check "CBC: 9 bytes -> 16" \
    test "$(ciphertext_size PRINCE-CBC 9 -iv "$iv")" -eq 16
check "CTR: 9 bytes -> 9" \
    test "$(ciphertext_size PRINCE-CTR 9 -iv "$iv")" -eq 9

for mode in OFB CFB; do
    for size in 0 1 7 8 9 16 17; do
        check "$mode: $size bytes -> $size" \
            test "$(ciphertext_size "PRINCE-$mode" "$size" -iv "$iv")" -eq "$size"
        check "$mode -nopad: $size bytes -> $size" \
            test "$(ciphertext_size "PRINCE-$mode" "$size" -iv "$iv" -nopad)" -eq "$size"
    done
done



# PRINCE paper vector: zero key and zero plaintext
ciphertext=$(head -c 8 /dev/zero |
    openssl enc "${provider_args[@]}" -PRINCE-ECB -nopad -K "$zero_key" |
    xxd -p)
check "PRINCE-ECB paper vector" \
    test "$ciphertext" = 818665aa0d02dfda

# RFC 4503 A.2: IV and keystream bytes use little-endian order here
keystream=$(head -c 16 /dev/zero |
    openssl enc "${provider_args[@]}" -RABBIT -K "$zero_key" -iv 597e26c175f573c3 |
    xxd -p)
check "RABBIT RFC 4503 keystream" \
    test "$keystream" = 6d7d012292ccdce0e2120058b94ecd1f


# Invalid input must be rejected
head -c 15 /dev/zero > "$work_dir/plain"
expect_failure "-nopad with 15 bytes must fail" \
    openssl enc "${provider_args[@]}" -PRINCE-CBC -nopad -K "$key" -iv "$iv" \
        -in "$work_dir/plain" -out "$work_dir/encrypted"

head -c 100 /dev/zero > "$work_dir/plain"
openssl enc "${provider_args[@]}" -PRINCE-CBC -K "$key" -iv "$iv" \
    -in "$work_dir/plain" -out "$work_dir/encrypted"
expect_failure "decrypting with the wrong key must fail (bad padding)" \
    openssl enc -d "${provider_args[@]}" -PRINCE-CBC \
        -K ffeeddccbbaa99887766554433221100 -iv "$iv" \
        -in "$work_dir/encrypted" -out "$work_dir/decrypted"

head -c 13 "$work_dir/encrypted" > "$work_dir/truncated"
expect_failure "decrypting a truncated ciphertext must fail" \
    openssl enc -d "${provider_args[@]}" -PRINCE-CBC -K "$key" -iv "$iv" \
        -in "$work_dir/truncated" -out "$work_dir/decrypted"

exit "$failed"
