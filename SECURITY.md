# Security Policy

## Supported versions

This community-maintained library applies security fixes to the **latest
released version** on Clojars. Upgrade to the latest release before you report
an issue.

## Scope

jose-clj is a thin Clojure wrapper over [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt).
It does not perform cryptography. Reports about this library concern its use of
the engine:

- key or algorithm selection,
- verification and validation logic,
- error handling that could mask a failed check, and
- unsafe defaults.

Report flaws in the underlying cryptographic primitives to the Nimbus JOSE+JWT
maintainers.

Regression tests cover two token-forgery classes. They must remain closed:

- algorithm confusion: an HS256 token forged with an asymmetric public key as
  the MAC secret;
- unsecured `alg:none` tokens.

A report that demonstrates either class against a released version is in scope.
We treat it as high severity.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Report them privately by email to **jsavyasachi@gmail.com** or by
GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
("Report a vulnerability" under the repository's **Security** tab).

Please include:

- a description of the issue and its impact;
- steps to reproduce or a proof of concept; and
- the affected version(s).

We send an initial acknowledgement in a reasonable time. After we confirm the
issue and release a fix, we publish the advisory with credit to the reporter.
Tell us if you do not want credit.
