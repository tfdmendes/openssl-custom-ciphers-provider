# Extending the OpenSSL command-line tool

![gif](/003.gif)

## Table of Contents
- [Repo Structure](#repo-structure)
- [TODO](#todo)


## Repo Structure

- **[README.md](/README.md):** this file.

- **[docs/ossl.pdf](/docs/ossl.pdf):** the project guidelines.

- **[docs/verification_report.md](/docs/verification_report.md):** what was tested, how, results and what is missing.

- **[docs/provider_design_decisions.md](/docs/provider_design_decisions.md):** our provider architecture decisions.

- **[bench/run_bench.sh](/bench/run_bench.sh):** benchmark script (`openssl speed -evp`).


## TODO

- [x] Block cipher       - One block cipher that was never part of OpenSSL
- [x] Stream cipher      - One stream cipher that was never part of OpenSSL
- [x] OpenSSL provider   - A dynamically loadable OpenSSL 3 provider
- [x] EVP cipher support - Both algorithms must be exposed through OSSL_OP_CIPHER
- [x] CLI integration    - Algorithms must be usable from the standard openssl tool
- [x] Benchmarking       - Algorithms must work with openssl speed -evp (script ready; final table and discussion pending)
- [x] File encryption    - Algorithms must encrypt whole files using openssl enc
- [x] File decryption    - Algorithms must decrypt whole files using openssl enc
- [ ] Validation         - Students must provide test vectors and automated checks
- [ ] Documentation      - Students must document design, build, usage, tests, and limitations
