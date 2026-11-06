# Resultado de `bash run_tests.sh` (PRINCE otimizado: SWAR + bitslicing)

Data: 2026-11-03T21:34:04Z

```text

Stages: build check benchmark report

------------------------------------------------------------------------------------------------------------------------

[1/4] BUILD

Build OK

------------------------------------------------------------------------------------------------------------------------

[2/4] CHECK: encryption/decryption

Test project /home/popo-caca/Uni/4/CA/Projeto/openssl-custom-ciphers-provider/build
    Start 1: test_prince
1/5 Test #1: test_prince ......................   Passed    0.00 sec
    Start 2: test_modes
2/5 Test #2: test_modes .......................   Passed    0.03 sec
    Start 3: test_rabbit
3/5 Test #3: test_rabbit ......................   Passed    0.01 sec
    Start 4: roundtrip
4/5 Test #4: roundtrip ........................   Passed    3.08 sec
    Start 5: test_provider
5/5 Test #5: test_provider ....................   Passed    0.00 sec

100% tests passed out of 5

Total Test time (real) =   3.13 sec

------------------------------------------------------------------------------------------------------------------------

[3/4] BENCHMARK: encryption speed

12 ciphers x 6 sizes x 3 s (~216 s total)
  [1/12] PRINCE-ECB
  [2/12] PRINCE-CBC
  [3/12] PRINCE-CTR
  [4/12] PRINCE-OFB
  [5/12] PRINCE-CFB
  [6/12] RABBIT
  [7/12] AES-128-ECB
  [8/12] AES-128-CBC
  [9/12] AES-128-CTR
  [10/12] AES-128-OFB
  [11/12] AES-128-CFB
  [12/12] ChaCha20

------------------------------------------------------------------------------------------------------------------------

[4/4] REPORT

Source: current run
Measured (UTC): 2026-11-03T21:34:07Z

Throughput: MB/s (megabytes per second)

+-------------+------------+---------+---------+----------+----------+----------+----------+
| Cipher      | Provider   | 16 B    | 64 B    | 256 B    | 1024 B   | 8192 B   | 16384 B  |
+-------------+------------+---------+---------+----------+----------+----------+----------+
| PRINCE-ECB  | customprov |   74.90 |  144.84 |   460.60 |   472.78 |   475.40 |   478.95 |
| PRINCE-CBC  | customprov |   67.03 |   69.94 |    71.07 |    71.32 |    71.07 |    71.39 |
| PRINCE-CTR  | customprov |   73.80 |  134.70 |   343.36 |   350.13 |   352.20 |   352.10 |
| PRINCE-OFB  | customprov |   68.36 |   70.03 |    70.92 |    71.11 |    70.95 |    71.17 |
| PRINCE-CFB  | customprov |   64.51 |   65.20 |    65.57 |    65.45 |    65.68 |    64.97 |
| RABBIT      | customprov |  592.74 |  663.77 |   678.74 |   687.33 |   685.78 |   688.81 |
| AES-128-ECB | default    | 1169.02 | 4917.39 | 10808.96 | 11964.84 | 12151.43 | 12185.44 |
| AES-128-CBC | default    | 1250.16 | 1507.21 |  1571.09 |  1594.53 |  1593.40 |  1595.29 |
| AES-128-CTR | default    | 1006.63 | 3308.06 |  6936.21 |  9701.31 | 10903.44 | 11063.50 |
| AES-128-OFB | default    | 1076.53 | 1305.52 |  1319.78 |  1324.41 |  1327.37 |  1321.82 |
| AES-128-CFB | default    |  932.88 |  961.94 |   968.18 |   967.70 |   968.96 |   969.83 |
| ChaCha20    | default    |  512.76 |  785.57 |  2045.56 |  4223.23 |  4383.03 |  4394.12 |
+-------------+------------+---------+---------+----------+----------+----------+----------+

Relative throughput: 100% = baseline

+------------+-------------+---------+--------+--------+--------+--------+---------+
| Cipher     | Baseline    | 16 B    | 64 B   | 256 B  | 1024 B | 8192 B | 16384 B |
+------------+-------------+---------+--------+--------+--------+--------+---------+
| PRINCE-ECB | AES-128-ECB |   6.41% |  2.95% |  4.26% |  3.95% |  3.91% |   3.93% |
| PRINCE-CBC | AES-128-CBC |   5.36% |  4.64% |  4.52% |  4.47% |  4.46% |   4.47% |
| PRINCE-CTR | AES-128-CTR |   7.33% |  4.07% |  4.95% |  3.61% |  3.23% |   3.18% |
| PRINCE-OFB | AES-128-OFB |   6.35% |  5.36% |  5.37% |  5.37% |  5.35% |   5.38% |
| PRINCE-CFB | AES-128-CFB |   6.91% |  6.78% |  6.77% |  6.76% |  6.78% |   6.70% |
| RABBIT     | ChaCha20    | 115.60% | 84.50% | 33.18% | 16.27% | 15.65% |  15.68% |
| RABBIT     | AES-128-CTR |  58.88% | 20.07% |  9.79% |  7.08% |  6.29% |   6.23% |
+------------+-------------+---------+--------+--------+--------+--------+---------+

Done.

Benchmark results:
  Throughput: /home/popo-caca/Uni/4/CA/Projeto/openssl-custom-ciphers-provider/build/results.md
  Comparison: /home/popo-caca/Uni/4/CA/Projeto/openssl-custom-ciphers-provider/build/comparison.md
  Environment and raw measurements: /home/popo-caca/Uni/4/CA/Projeto/openssl-custom-ciphers-provider/build/environment.log
exit code: 0
```
