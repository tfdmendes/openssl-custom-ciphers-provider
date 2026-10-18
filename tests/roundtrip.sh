#!/usr/bin/env bash
# Round-trip and known-answer tests through the real `openssl enc` CLI.
# Usage: roundtrip.sh <directory containing customprov.so>
set -u

PROV_DIR=${1:?usage: roundtrip.sh <provider dir>}
OPT=(-provider-path "$PROV_DIR" -provider default -provider customprov)
KEY=00112233445566778899aabbccddeeff
IV=0102030405060708
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
fail=0

check() { # check <description> <command...>
    local desc=$1; shift
    if "$@" >/dev/null 2>&1; then echo "ok   $desc"; else echo "FAIL $desc"; fail=1; fi
}

fails() { # fails <description> <command...>: the command must exit non-zero
    local desc=$1; shift
    if "$@" >/dev/null 2>&1; then echo "FAIL $desc (expected an error)"; fail=1; else echo "ok   $desc"; fi
}

roundtrip() { # roundtrip <algorithm> <size> [extra enc args...]
    local alg=$1 size=$2; shift 2
    head -c "$size" /dev/urandom > "$WORK/plain"
    openssl enc "${OPT[@]}" "-$alg" -K "$KEY" "$@" -in "$WORK/plain" -out "$WORK/enc" &&
    openssl enc -d "${OPT[@]}" "-$alg" -K "$KEY" "$@" -in "$WORK/enc" -out "$WORK/dec" &&
    cmp -s "$WORK/plain" "$WORK/dec"
}

# 1. Round-trip for every mode and input size (empty, 1 byte, block-1/block/block+1, many blocks, large).
for mode in ECB CBC CTR; do
    for size in 0 1 7 8 9 16 17 1000 1000000 20000000; do
        if [ "$mode" = ECB ]; then
            check "PRINCE-$mode round-trip, $size bytes" \
                roundtrip "PRINCE-$mode" "$size"
        else
            check "PRINCE-$mode round-trip, $size bytes" \
                roundtrip "PRINCE-$mode" "$size" -iv "$IV"
        fi
    done
done

for size in 0 1 15 16 17 1000 1000000 20000000; do
    check "RABBIT round-trip, $size bytes" roundtrip RABBIT "$size" -iv "$IV"
done

check "PRINCE-CBC -nopad round-trip, 64 bytes" roundtrip PRINCE-CBC 64 -iv "$IV" -nopad

# 2. Ciphertext sizes: padding adds 1..8 bytes, CTR adds none.
size_of() {
    head -c "$2" /dev/zero |
        openssl enc "${OPT[@]}" "-$1" -K "$KEY" ${3:+-iv "$IV"} |
        wc -c |
        tr -d '[:space:]'
}

[ "$(size_of PRINCE-ECB 8)" = 16 ]        && echo "ok   ECB: 8 bytes -> 16 (full padding block)" || { echo "FAIL ECB size"; fail=1; }
[ "$(size_of PRINCE-CBC 9 iv)" = 16 ]     && echo "ok   CBC: 9 bytes -> 16" || { echo "FAIL CBC size"; fail=1; }
[ "$(size_of PRINCE-CTR 9 iv)" = 9 ]      && echo "ok   CTR: 9 bytes -> 9" || { echo "FAIL CTR size"; fail=1; }

# 3. Known answer through the CLI: paper test vector (key 0, plaintext 0 -> 818665aa0d02dfda).
kat=$(printf '\0\0\0\0\0\0\0\0' | openssl enc "${OPT[@]}" -PRINCE-ECB -nopad -K 00000000000000000000000000000000 | xxd -p)
[ "$kat" = 818665aa0d02dfda ] && echo "ok   PRINCE-ECB paper vector" || { echo "FAIL paper vector ($kat)"; fail=1; }

# Rabbit keystream, RFC 4503 A.2 (all-zero key, IV C373F575C1267E59 written little-endian):
# encrypting zeros returns the keystream, whose first 16 bytes are the RFC's S[0] reversed.
kat=$(head -c 16 /dev/zero | openssl enc "${OPT[@]}" -RABBIT -K 00000000000000000000000000000000 -iv 597e26c175f573c3 | xxd -p)
[ "$kat" = 6d7d012292ccdce0e2120058b94ecd1f ] && echo "ok   RABBIT RFC 4503 keystream" || { echo "FAIL RABBIT keystream ($kat)"; fail=1; }

# 4. Negative tests.
fails "-nopad with 15 bytes must fail" \
    bash -c 'head -c 15 /dev/zero | openssl enc "$@" -PRINCE-CBC -nopad -K '"$KEY"' -iv '"$IV" _ "${OPT[@]}"
head -c 100 /dev/zero | openssl enc "${OPT[@]}" -PRINCE-CBC -K "$KEY" -iv "$IV" -out "$WORK/enc"
fails "decrypting with the wrong key must fail (bad padding)" \
    openssl enc -d "${OPT[@]}" -PRINCE-CBC -K ffeeddccbbaa99887766554433221100 -iv "$IV" -in "$WORK/enc"
head -c 13 "$WORK/enc" > "$WORK/trunc"
fails "decrypting a truncated ciphertext must fail" \
    openssl enc -d "${OPT[@]}" -PRINCE-CBC -K "$KEY" -iv "$IV" -in "$WORK/trunc"

exit $fail
