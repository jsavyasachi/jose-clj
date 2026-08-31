# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- **Breaking:** JWS and JWT verification through JWKS sources now rejects keys marked for encryption or without the `verify` key operation. Keys with absent usage metadata remain accepted.

## [0.8.0] - 2026-08-30

### Security

- **Breaking:** `jose.proc/processor` no longer lets a supplied `:jws-key-selector` disable a configured `:jws-algs` allow-list. Previously, passing a key selector silently widened the policy: a processor built with `:jws-algs #{:rs256}` and an `:rsa` family selector accepted `RS512`. A selector may now only narrow the accepted algorithms, and the effective allow-list is the intersection of the configuration and the selector. Processors configured without `:jws-algs` still derive their algorithms from the selector alone.

### Changed

- **Breaking:** Removed the internal `jws-policy?` field from the `jose.proc/Processor` record. It existed only to suppress the allow-list check described above.

## [0.7.1] - 2026-08-28

### Fixed

- Fixed OKP-to-Java-key conversion on JDK 11: Ed25519 and X25519 algorithms now reported `:key-import-failure` with the algorithm and required JDK instead of raising `NoSuchAlgorithmException`.
- Corrected the documented JDK support: the library requires JDK 11, while OKP-to-JCA conversion requires JDK 15 or newer.
- Cleared the clj-kondo warnings that had failed the lint gate.

## [0.7.0] - 2026-08-28

### Added

- Added `jose.mint` for minting JWS values with a signing key selected from a JWKS source and an optional custom signer factory.
- Added `jose.proc` for generic JOSE processing, algorithm-family and single-key JWS selectors, per-call JWK security contexts, matcher predicates, and custom verifier and decrypter factories.
- Added X.509 certificate-chain parsing and rendering, JWK `x5c` conversion, parsed-certificate access, JWK-to-Java-key conversion including OKP keys, and whole-key-store loading with per-alias passwords in `jose.jwk` and `jose.pem`.
- Added JCA provider selection, BouncyCastle and BouncyCastle-FIPS singletons, and the `:secure-random`, `:max-compressed-length`, `:cipher-mode`, and `:allow-weak-rsa-key?` options.
- Added deferred JWS signing with `:user-authentication-required?`, returning the initialized `java.security.Signature` and a completion function.
- Added the fully specified `Ed25519` JWS algorithm alongside `EdDSA`.
- Documented the library's scope and the known Nimbus 10.9.1 limitation that EdDSA verification through a JWKS source does not resolve keys.

### Fixed

- Fixed JWS JSON serialization to enforce RFC 7515 section 7.2.1 header disjointness: `sign-json` refuses overlapping protected and unprotected headers, and `verify-json` rejects them in every signature of a general serialization.

## [0.6.1] - 2026-08-24

### Fixed

- validate-algorithm now correctly validates string-form algorithm values via JWSAlgorithm/parse instead of skipping validation due to an unreachable cond branch.

## [0.6.0] - 2026-08-24

### Added

- Added reusable JWT processors via `build-processor` and `process-with-processor`.
- Added tenant- and issuer-aware JWT key selection.
- Added `jose.ring` with Bearer-auth Ring middleware.
- Added RFC 7797 detached and unencoded-payload JWS support.
- Hardened remote JWKS transport with HTTPS enforcement, size and timeout limits, and a custom resource retriever.
- Added JWK generator options for `SecureRandom`, `Provider`, and `KeyStore`.
- Added JWK metadata accessors for use, operations, algorithm, timestamps, key ID, and X.509 chain.
- Added a validated JWT policy builder with diagnostic errors.
- Added a generative/property-based test suite using `test.check`.

## [0.5.1] - 2026-08-17

### Security

- Reject the RSA1_5 (RSAES-PKCS1-v1_5) key-management algorithm on the
  decryption paths (`decrypt` and `decrypt-json`), matching the existing
  encrypt-side rejection. Accepting it on decrypt left the Bleichenbacher
  padding-oracle exposure open.

## [0.5.0] - 2026-07-16
### Added
- Nimbus JOSE parity pass. All additions are backward compatible and preserve the secure-by-default posture (`alg:none`, RSA1_5, and deprecated algorithms remain rejected).
- **JWT processor pipeline**: `process`/`processor` over `DefaultJWTProcessor` for signed, encrypted, and nested tokens with a key selector, required expected algorithms, optional `typ` verification, and claims verification.
- **Extensible claims verification**: `claims-verifier`/`verify-claims` supporting exact-match claims, multiple/any audience, prohibited claims, and an injectable custom verifier.
- **Generic inspection**: `parse`/`parse-type` report token type and header without establishing trust.
- **Caller-supplied crypto providers**: `sign`/`verify`/`encrypt`/`decrypt` accept ready-made JWS/JWE signer/verifier/encrypter/decrypter instances (HSM/KMS/PKCS#11); the algorithm allow-list is still enforced.
- **Registered JOSE headers**: `jku`, `jwk`, `x5u`, `x5c`, `x5t`, `x5t#S256`, `typ`, `cty`, `crit`, and JWE `zip` compression, with round-trip on read.
- **PBES2/ECDH-1PU parity in JWE JSON**: `decrypt-json` accepts password-based and ECDH-1PU keys, matching compact `decrypt`.
- **Resilient remote JWKS**: `JWKSourceBuilder`-backed options (refresh-ahead, retry, failover, stale-key tolerance, cache control).
- **Full JWK matching/selection** (`jose.jwks/matcher`): key_ops, curves, sizes, public/private, x5t.
- **Complete JWK metadata generation**: key_ops, x5c/x5u/x5t, validity times, revocation.
- **X.509 / KeyStore interop**: `certificate->jwk`, `keystore->jwk`, `pem->certificate`.
- **Advanced JWKSet ops**: `load-set`, `set-contains?`, `filter-set`, `set-members`, `public-jwk-set` (strips private material via `toPublicJWKSet`).
- **RFC 9278 thumbprint URI**: `thumbprint-uri`.

## [0.4.0] - 2026-07-16
### Added
- Added `jose.keyring` for rotating active signing and encryption keys, retaining and pruning retired keys, and publishing public-only JWKS.
- Added PBES2-HS256/384/512+A128/192/256KW, ECDH-1PU and ECDH-1PU+A128/192/256KW, and XC20P JWE support.
- Added flattened and general JSON serialization for JWS and JWE, including multiple signatures and recipients.

## [0.3.0] - 2026-07-16
### Changed
- **BREAKING**: verify/unsign now require an expected algorithm (`:algs`) and reject unexpected algorithms by default (RFC 8725); pass `{:algs #{...}}`, or `{:algs :any}` to opt out. `alg:none` is always rejected.

### Added
- Added `:typ`/`:cty` header checks, `:crit` understood-header validation, and `:max-age` token-age validation for JWS/JWT verification.

## [0.2.0] - 2026-07-10
### Added
- Added `jose.pem` for PEM public keys, private keys, and X.509 certificates to JWK maps, plus JWK to PEM export.
- Added detached JWS serialization and verification with `:detached?` and `verify-detached`.
- Added RFC 7797 unencoded JWS payload signing and verification with `:b64? false`.

## [0.1.2] - 2026-07-09
### Fixed
- POM now includes the project description, homepage URL, and full SCM connection metadata, so Clojars shows a description/homepage and cljdoc has complete source-link data.
