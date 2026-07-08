# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## [0.1.1] - 2026-07-08

### Changed

- Lower the supported JDK floor from 17 to 11. The library already ran on JDK 11
  (Nimbus JOSE+JWT targets Java 7 bytecode; Tink and BouncyCastle target Java 8);
  the previous 17 requirement was not real. CI now covers JDK 11, 17, and 21.


## [0.1.0] - 2026-07-08

### Added

- Add `jose.jwk` for JWK generation, parsing, conversion, inspection, and JWK sets.
- Add `jose.jws` for compact JWS signing, verification, unverified headers, and binary payload access.
- Add `jose.jwt` for signed JWT creation, verification, unverified claims, and registered-claim validation.
- Add `jose.jwe` for compact JWE encryption, decryption, unverified headers, and binary payload access.
- Add encrypted JWT and nested sign-then-encrypt JWT support to `jose.jwt`.
- Add `jose.jwks` for local and remote JWKS sources, cached remote key selection, and `verify-with-jwks` helpers for JWS and JWT verification.
