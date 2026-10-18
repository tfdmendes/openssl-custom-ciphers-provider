# OpenSSL custom ciphers provider

![gif](003.gif)

An OpenSSL 3 provider that adds PRINCE and Rabbit to the standard `openssl` CLI for file encryption, decryption and benchmarks.

| Cipher | Key | IV | Padding |
|---|---|---|---|
| `PRINCE-ECB` | 16 bytes | None | PKCS#7 |
| `PRINCE-CBC` | 16 bytes | 8 bytes | PKCS#7 |
| `PRINCE-CTR` | 16 bytes | 8 bytes | None |
| `RABBIT` | 16 bytes | 8 bytes | None |

## Build and test

On Linux, install a C99 compiler, CMake, Bash, OpenSSL 3.x with development headers, `cmp` and `xxd`. Benchmark comparisons also need Python 3.9+. The OpenSSL 3 CLI must be on `PATH`.

Run from the repository root:

```bash
bash run_tests.sh
```

This creates a Release build in `build` and runs five test suites covering cipher vectors, modes, EVP integration and CLI round trips up to 20 MB. The provider is `build/customprov.so`. The root Makefile only builds standalone tests.

## Use

List our ciphers:

```bash
openssl list -provider-path ./build -provider customprov \
    -propquery 'provider=customprov' -cipher-algorithms
```

`-provider-path` locates the module, `-provider` loads it and `-propquery` filters the listing.

Encrypt, decrypt and compare a sample file:

```bash
key=00112233445566778899aabbccddeeff
iv=0102030405060708
printf 'Provider example\n' > build/plaintext.txt

openssl enc -provider-path ./build -provider default -provider customprov \
    -PRINCE-CBC -K "$key" -iv "$iv" \
    -in build/plaintext.txt -out build/ciphertext.enc

openssl enc -d -provider-path ./build -provider default -provider customprov \
    -PRINCE-CBC -K "$key" -iv "$iv" \
    -in build/ciphertext.enc -out build/decrypted.txt

cmp build/plaintext.txt build/decrypted.txt
```

`-K` and `-iv` take hexadecimal values, `-in` and `-out` select files, and `-d` decrypts. `cmp` prints nothing when the files match. The default provider keeps standard OpenSSL operations available.

Replace `-PRINCE-CBC` with `-PRINCE-CTR` or `-RABBIT` to try them. For ECB, use `-PRINCE-ECB` and omit `-iv`. ECB/CBC accept `-nopad` for plaintext lengths divisible by 8.

## Benchmarks

After building and testing:

```bash
bash bench/run_bench.sh build 3 > build/results.md 2> build/environment.log
python3 bench/compare_results.py build/results.md > build/comparison.md
```

The first argument to `run_bench.sh` is the provider directory. The second is seconds per cipher and input size; the default is 3, about 144 seconds of measurement. The commands save both tables and the environment log in `build`. Press Ctrl+C to stop.

Throughput is in decimal MB/s. In the comparison, 100% means equal speed and 50% means half the baseline speed. See the [saved results](bench/results/2026-10-18/README.md).

## Notes

- The example key and IV are for testing. Use fresh IVs; never reuse a key/IV pair with CTR or Rabbit.
- Encryption does not authenticate files. ECB exposes repeated blocks. The implementation has no constant-time guarantee.
- PRINCE has a 64-bit block size. Benchmark results apply to this implementation and machine.

See [cipher selection and sources](docs/cipher_selection.md), the [PRINCE](docs/prince_cipher_explaination.md) and [Rabbit](docs/rabbit_cipher_explaination.md) explanations, and the [project brief](docs/ossl.pdf). The course report is separate.
