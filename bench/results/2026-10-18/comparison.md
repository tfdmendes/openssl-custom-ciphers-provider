# Relative throughput

Custom throughput / baseline throughput x 100. Higher is faster.

100% = equal throughput; 50% = half; 200% = twice.

| Cipher | Baseline | 16 B | 64 B | 256 B | 1024 B | 8192 B | 16384 B |
|---|---|---:|---:|---:|---:|---:|---:|
| PRINCE-ECB | AES-128-ECB | 0.51% | 0.21% | 0.15% | 0.14% | 0.16% | 0.15% |
| PRINCE-CBC | AES-128-CBC | 0.40% | 0.30% | 0.28% | 0.27% | 0.28% | 0.28% |
| PRINCE-CTR | AES-128-CTR | 0.86% | 0.13% | 0.06% | 0.05% | 0.04% | 0.04% |
| RABBIT | ChaCha20 | 177.30% | 164.25% | 84.41% | 47.18% | 48.34% | 47.44% |

Ratios use the rounded throughput values in the input table.
