# Security Policy

## Supported versions

This is a community-maintained library. Security fixes are applied to the
**latest released version** on Clojars. Please upgrade to the latest release
before reporting an issue.

## Scope

jose-clj is a thin Clojure wrapper over [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt);
it performs no cryptography of its own. Reports about this library concern how it
uses the engine: key or algorithm selection, verification and validation logic,
error handling that could mask a failed check, and unsafe defaults. Flaws in the
underlying cryptographic primitives should be reported to the Nimbus JOSE+JWT
maintainers upstream.

Two token-forgery classes are covered by regression tests and must stay closed:
algorithm confusion (an HS256 token forged with an asymmetric public key as the
MAC secret) and unsecured `alg:none` tokens. A report demonstrating either against
a released version is in scope and will be treated as high severity.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, report them privately by email to **jsavyasachi@gmail.com**, or via
GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
("Report a vulnerability" under the repository's **Security** tab).

Please include:

- a description of the issue and its impact,
- steps to reproduce (or a proof of concept), and
- the affected version(s).

You can expect an initial acknowledgement within a reasonable time. Once the
issue is confirmed and a fix is released, the advisory will be published with
credit to the reporter unless you request otherwise.
