# OpenSSL custom ciphers provider

Adds PRINCE and Rabbit to OpenSSL 3 for file encryption, decryption and performance measurements.

| Cipher | Key | IV | Padding |
|---|---|---|---|
| `PRINCE-ECB` | 16 bytes | None | PKCS#7 |
| `PRINCE-CBC` | 16 bytes | 8 bytes | PKCS#7 |
| `PRINCE-CTR` | 16 bytes | 8 bytes | None |
| `RABBIT` | 16 bytes | 8 bytes | None |

## Requirements

A C99 compiler, CMake 3.16 or newer, Bash, OpenSSL 3.x with development headers and libraries, and the tools `awk`, `cmp`, `xxd` and `mktemp`.

On Linux, the `openssl` command on `PATH` must use OpenSSL 3. On macOS, the script selects Homebrew `openssl@3` for compilation and execution.

## Run

Run these commands from the repository root:

```bash
bash run_tests.sh
```

With no stage names, or with `all`, the script runs four stages in order:

| Stage | Action |
|---|---|
| `build` | Compile the provider and test programs in Release mode |
| `check` | Run five suites covering known cipher results, modes, padding, OpenSSL integration and file round trips up to 20 MB |
| `benchmark` | Measure fresh encryption speeds and save throughput and comparison tables |
| `report` | Display the saved tables and their measurement timestamp |

Select stages by name. They run in the order above, with repeated names executed once. `check` and `benchmark` use the existing build, so include `build` after source changes.

```bash
# Rebuild and check cipher results
bash run_tests.sh build check

# Measure fresh performance and display the tables
bash run_tests.sh benchmark report --seconds 1

# Display saved measurements
bash run_tests.sh report
```

`--seconds N` sets a positive integer duration per cipher and input size. The default is 3, about 144 seconds of benchmarks; `--seconds 1` takes about 48 seconds. Build and check time is additional. The option requires the `benchmark` stage. Use `bash run_tests.sh --help` for more examples.

The script stops if a stage fails. Press Ctrl+C to stop a run.

## Results

| File | Contents |
|---|---|
| `build/results.md` | Throughput from the latest successful benchmark, with its timestamp |
| `build/comparison.md` | PRINCE versus AES-128 in each mode; Rabbit versus ChaCha20 and AES-128-CTR |
| `build/environment.log` | Benchmark configuration, OpenSSL version, CPU details and raw measurements |
| `build/build.log` | Compilation output, also shown in the terminal if compilation fails |

`benchmark` replaces the previous benchmark outputs and writes the tables after all measurements succeed. `report` reads those saved tables. The compiled provider is `build/customprov.so` on Linux or `build/customprov.dylib` on macOS.

Benchmarks use `openssl speed -evp` with elapsed wall-clock time and input sizes of 16, 64, 256, 1024, 8192 and 16384 bytes. Rates are **MB/s (megabytes per second)**, where 1 MB is 1,000,000 bytes. Relative throughput is the custom cipher rate divided by the baseline rate, multiplied by 100: 100% means equal speed and 50% means half the baseline speed. Percentages use unrounded measurements.

Speed depends on the machine, system load and hardware acceleration. Benchmarks report measurements without enforcing performance thresholds.

## Encrypt and decrypt files

Build the provider first. On macOS, select OpenSSL 3 for the current terminal session before running the commands below:

```bash
export PATH="$(brew --prefix openssl@3)/bin:$PATH"
```

List the provider's ciphers:

```bash
openssl list -provider-path ./build -provider customprov \
    -propquery 'provider=customprov' -cipher-algorithms
```

`-provider-path` selects the module directory, `-provider` loads a provider and `-propquery` filters the listing to our provider.

Try a PRINCE-CBC round trip:

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

`-K` and `-iv` take hexadecimal values. `-in` and `-out` select files; `-d` decrypts. Loading `default` keeps standard OpenSSL operations available. `cmp` prints nothing if the files match.

Use `-PRINCE-CTR` or `-RABBIT` to try the other IV-based ciphers. For `-PRINCE-ECB`, omit `-iv`. ECB and CBC accept `-nopad` for plaintext lengths divisible by 8.

## Notes

- The example key and IV are for testing. Use fresh IVs; never reuse a key/IV pair with CTR or Rabbit.
- Encryption does not authenticate files. ECB exposes repeated blocks. The implementation has no constant-time guarantee.
- PRINCE has a 64-bit block size.

See the [project brief](docs/ossl.pdf) and the [PRINCE paper](docs/prince_cipher_paper.pdf).
