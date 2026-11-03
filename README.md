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

On Linux, install a C99 compiler, CMake, Bash, OpenSSL 3.x with development headers, `awk`, `cmp` and `xxd`. The OpenSSL 3 CLI must be on `PATH`. On macOS, the script uses Homebrew `openssl@3` for both compilation and execution.

Run from the repository root:

```bash
bash run_tests.sh
```

This single command announces and runs four stages:

1. Compile the provider and test programs in Release mode into `build`. The provider is `build/customprov.so` on Linux and `build/customprov.dylib` on macOS. Compilation output goes to `build/build.log` and is shown in the terminal if the build fails.
2. Run five test suites to check known cipher results, encryption and decryption, ECB/CBC/CTR modes, PKCS#7 padding, OpenSSL integration and CLI file round trips up to 20 MB. These tests check that our implementation produces the expected output and rejects invalid input.
3. Measure fresh encryption performance for PRINCE-ECB/CBC/CTR and Rabbit, alongside AES-128-ECB/CBC/CTR and ChaCha20. Progress shows one line per cipher. Convert the rates to MB/s, calculate the relative speeds and save both tables.
4. Display both saved tables with their measurement timestamp. The script explains the units and percentage calculation alongside the output.

Select individual stages by name, or combine them:

```bash
# Compile the provider and test programs
bash run_tests.sh build

# Run the five test suites using the existing build
bash run_tests.sh check

# Compile source changes and then run the test suites
bash run_tests.sh build check

# Measure fresh performance and display the tables, using the existing build
bash run_tests.sh benchmark report --seconds 1

# Display the saved tables with their measurement timestamp
bash run_tests.sh report

# Show available stages and options
bash run_tests.sh --help
```

Only the named stages run, always in the order `build`, `check`, `benchmark`, `report`. Repeated names run once. With no stage names, or with `all`, every stage runs. `check` and `benchmark` require an existing compiled build; include `build` to compile first, especially after source changes. `check` also verifies that all five suites are registered before running them. `benchmark` saves fresh results even when `report` is not selected. `report` alone displays saved results and explicitly states that no new measurements were requested. Only `benchmark` replaces the saved tables and environment log.

The default benchmark uses three seconds per cipher and input size, about 144 seconds plus any selected build and check stages. Stop with Ctrl+C. The script stops if a selected stage fails. The root Makefile only builds standalone tests; `run_tests.sh` is the single entry point for all stages.

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

The `benchmark` stage measures all eight ciphers with input sizes of 16, 64, 256, 1024, 8192 and 16384 bytes. The measurements use `openssl speed -evp` for encryption and elapsed wall-clock time. It saves:

- `build/results.md`: encryption throughput from the latest successful benchmark, with its timestamp.
- `build/comparison.md`: each PRINCE mode relative to AES-128 in the same mode, and Rabbit relative to ChaCha20.
- `build/environment.log`: timestamp, OpenSSL version and configuration, CPU information and raw benchmark output.

The two output tables are removed when the `benchmark` stage starts and are written again only after all measurements succeed. The environment log is overwritten for that benchmark. `build`, `check` and `report` preserve these files. The `report` stage prints the two tables and their measurement timestamp. Existing files under `build/benchmarks` are left in place and are never read by the script.

Throughput is in **MB/s (megabytes per second)**: 1 MB is 1,000,000 bytes. Uppercase `B` means bytes; lowercase `b` means bits. **1 MB/s = 8 Mb/s**. Higher throughput is faster. In the comparison, 100% means equal speed, 50% means half the baseline speed and 200% means twice the baseline speed. Percentages use the measurements before rounding for display.

For a shorter complete run, use `bash run_tests.sh --seconds 1`. The `--seconds` option sets the seconds per cipher and input size, so benchmarks take about 48 seconds. It applies to that invocation and requires the `benchmark` stage to be selected. Results depend on the machine, system load and available hardware acceleration; they are speed measurements rather than pass/fail performance thresholds.

## Notes

- The example key and IV are for testing. Use fresh IVs; never reuse a key/IV pair with CTR or Rabbit.
- Encryption does not authenticate files. ECB exposes repeated blocks. The implementation has no constant-time guarantee.
- PRINCE has a 64-bit block size. Benchmark results apply to this implementation and machine.

See [cipher selection and sources](docs/cipher_selection.md), the [PRINCE](docs/prince_cipher_explaination.md) and [Rabbit](docs/rabbit_cipher_explaination.md) explanations, and the [project brief](docs/ossl.pdf). The course report is separate.
