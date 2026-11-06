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
checked=0
passed=0


# If command fails, record failure and continue testing
check() {
    local description=$1
    shift

    checked=$((checked + 1))
    if "$@"; then
        passed=$((passed + 1))
    else
        echo "FAIL $description"
        failed=1
    fi
}

# Whenever the command must fail, hide its output
expect_failure() {
    local description=$1
    shift

    checked=$((checked + 1))
    if "$@" >/dev/null 2>&1; then
        echo "FAIL $description (expected an error)"
        failed=1
    else
        passed=$((passed + 1))
    fi
}

report_group() {
    local description=$1 checked_before=$2 passed_before=$3
    local total=$((checked - checked_before)) successes=$((passed - passed_before)) status=PASS

    if [ "$successes" -ne "$total" ]; then status=FAIL; fi
    printf '[%s] %s: %s/%s checks passed\n' "$status" "$description" "$successes" "$total"
}

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

    # BSD head rejects zero bytes, so create an empty file directly
    if [ "$size" -eq 0 ]; then
        printf '' > "$work_dir/plain" || return 1
    else
        head -c "$size" /dev/zero > "$work_dir/plain" || return 1
    fi
    openssl enc "${provider_args[@]}" "-$algorithm" -K "$key" "$@" -in "$work_dir/plain" |
        wc -c |
        tr -d '[:space:]'
}

check_ciphertext_size() {
    local algorithm=$1 size=$2 expected=$3 actual
    shift 3

    actual=$(ciphertext_size "$algorithm" "$size" "$@") || return 1
    if [ "$actual" -ne "$expected" ]; then
        printf 'Expected %s bytes, received %s\n' "$expected" "$actual"
        return 1
    fi
}


# Round trips around block boundaries and up to 20 MB
for mode in ECB CBC CTR OFB CFB; do
    checked_before=$checked
    passed_before=$passed
    for size in 0 1 7 8 9 16 17 1000 1000000 20000000; do
        if [ "$mode" = ECB ]; then
            check "PRINCE-$mode round-trip, $size bytes" \
                roundtrip "PRINCE-$mode" "$size"
        else
            check "PRINCE-$mode round-trip, $size bytes" \
                roundtrip "PRINCE-$mode" "$size" -iv "$iv"
        fi
    done
    report_group "PRINCE-$mode round trips (0 to 20 MB)" "$checked_before" "$passed_before"
done

checked_before=$checked
passed_before=$passed
for size in 0 1 15 16 17 1000 1000000 20000000; do
    check "RABBIT round-trip, $size bytes" \
        roundtrip RABBIT "$size" -iv "$iv"
done
report_group 'RABBIT round trips (0 to 20 MB)' "$checked_before" "$passed_before"


# Padding adds a full block to aligned input; stream modes preserve the size
checked_before=$checked
passed_before=$passed
check "PRINCE-CBC -nopad round-trip, 64 bytes" \
    roundtrip PRINCE-CBC 64 -iv "$iv" -nopad
check "ECB: 8 bytes -> 16" \
    check_ciphertext_size PRINCE-ECB 8 16
check "CBC: 9 bytes -> 16" \
    check_ciphertext_size PRINCE-CBC 9 16 -iv "$iv"
check "CTR: 9 bytes -> 9" \
    check_ciphertext_size PRINCE-CTR 9 9 -iv "$iv"

for mode in OFB CFB; do
    for size in 0 1 7 8 9 16 17; do
        check "$mode: $size bytes -> $size" \
            check_ciphertext_size "PRINCE-$mode" "$size" "$size" -iv "$iv"
        check "$mode -nopad: $size bytes -> $size" \
            check_ciphertext_size "PRINCE-$mode" "$size" "$size" -iv "$iv" -nopad
    done
done
report_group 'Padding and ciphertext sizes' "$checked_before" "$passed_before"



known_answer() {
    local number=$1 description=$2 vector_key=$3 vector_iv=$4 input=$5 expected=$6 result=$7
    local color= reset= status=FAIL

    if [ "$result" = "$expected" ]; then
        status=PASS
    else
        failed=1
    fi
    if [ -z "${NO_COLOR:-}" ] && { { [ -n "${CLICOLOR_FORCE:-}" ] && [ "$CLICOLOR_FORCE" != 0 ]; } ||
        { [ -t 1 ] && [ "${TERM:-}" != dumb ]; }; }; then
        if [ "$status" = PASS ]; then color=$'\033[32m'; else color=$'\033[31m'; fi
        reset=$'\033[0m'
    fi
    printf '\nTest %s (%s)\n- Key: %s\n' "$number" "$description" "$vector_key"
    if [ -n "$vector_iv" ]; then printf '%s\n' "- IV: $vector_iv"; fi
    printf '%s\n' "- Original Text: $input" "- Expected Result: $expected"
    printf '%s- Result: %s [%s]%s\n' "$color" "$result" "$status" "$reset"
}

# PRINCE paper vector: zero key and zero plaintext
if ciphertext=$(head -c 8 /dev/zero |
    openssl enc "${provider_args[@]}" -PRINCE-ECB -nopad -K "$zero_key" |
    xxd -p); then :; else ciphertext='(operation failed)'; fi
known_answer 1 "PRINCE-ECB paper vector" "$zero_key" "" \
    0000000000000000 818665aa0d02dfda "$ciphertext"

# RFC 4503 A.2: IV and keystream bytes use little-endian order here
if keystream=$(head -c 16 /dev/zero |
    openssl enc "${provider_args[@]}" -RABBIT -K "$zero_key" -iv 597e26c175f573c3 |
    xxd -p); then :; else keystream='(operation failed)'; fi
known_answer 2 "RABBIT RFC 4503 keystream" "$zero_key" 597e26c175f573c3 \
    00000000000000000000000000000000 6d7d012292ccdce0e2120058b94ecd1f "$keystream"


# Invalid input must be rejected
checked_before=$checked
passed_before=$passed
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
report_group 'Invalid input rejection' "$checked_before" "$passed_before"

exit "$failed"
