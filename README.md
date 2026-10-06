# Extending the OpenSSL command-line tool

![gif](/003.gif)

## Table of Contents
- [Repo Structure](#repo-structure)
- [TODO](#todo)


## Repo Structure

- **[README.md](/README.md):** this file.

- **[ossl.pdf](/ossl.pdf):** the project guidelines.


## TODO

- [ ] Block cipher       - One block cipher that was never part of OpenSSL
- [ ] Stream cipher      - One stream cipher that was never part of OpenSSL
- [ ] OpenSSL provider   - A dynamically loadable OpenSSL 3 provider
- [ ] EVP cipher support - Both algorithms must be exposed through OSSL_OP_CIPHER
- [ ] CLI integration    - Algorithms must be usable from the standard openssl tool
- [ ] Benchmarking       - Algorithms must work with openssl speed -evp
- [ ] File encryption    - Algorithms must encrypt whole files using openssl enc
- [ ] File decryption    - Algorithms must decrypt whole files using openssl enc
- [ ] Validation         - Students must provide test vectors and automated checks
- [ ] Documentation      - Students must document design, build, usage, tests, and limitations
