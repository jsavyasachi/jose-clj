# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-07-10
### Added
- Added `jose.pem` for PEM public keys, private keys, and X.509 certificates to JWK maps, plus JWK to PEM export.
- Added detached JWS serialization and verification with `:detached?` and `verify-detached`.
- Added RFC 7797 unencoded JWS payload signing and verification with `:b64? false`.

## [0.1.2] - 2026-07-09
### Fixed
- POM now includes the project description, homepage URL, and full SCM connection metadata, so Clojars shows a description/homepage and cljdoc has complete source-link data.
