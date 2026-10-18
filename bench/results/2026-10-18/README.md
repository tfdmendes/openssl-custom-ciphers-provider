# Benchmark run: 18 October 2026

This is a saved copy of run `20261018T162049Z.xklQ76`, measured with the code committed as `e904606`.

| Setting | Value |
|---|---|
| CPU | Apple M2, 8 logical CPUs |
| System | Darwin 27.0.0, arm64 |
| OpenSSL | 3.6.5, CLI and provider linked to OpenSSL 3 |
| Compiler | Apple Clang 21.0.0 |
| Build | Release, with `-O3` and `-DNDEBUG` |
| Duration | 3 seconds per cipher and input size |
| Input sizes | 16, 64, 256, 1024, 8192 and 16384 bytes |

Command, run from the repository root:

```bash
bash bench/run_and_save.sh 3
```

- [Results](results.md): 48 throughput measurements, in decimal MB/s
- [Comparison](comparison.md): 24 percentages, calculated from the rounded throughput values
- [Environment](environment.txt): the saved environment log, including the exact compile command

All five test suites passed before measurement. The comparison percentages were checked against the saved throughput table. The tables are copied without changing their values. The environment log is saved as `.txt` so it is not excluded by the repository's `*.log` rule.

In this run, Rabbit was faster than ChaCha20 at 16 and 64 bytes and slower at larger sizes. PRINCE was slower than the matching AES modes at every tested size.

This is one run. It does not quantify variation between runs. OpenSSL used its normal runtime implementation selection; the active acceleration paths were not profiled. The performance gaps include the cipher, mode and provider implementations.
