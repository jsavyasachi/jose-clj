# Providers and crypto options

The compact `jose.jws/sign` and `verify` functions accept `:provider` and
`:secure-random`. A provider is either a `java.security.Provider` or
`:bouncy-castle` / `:bouncy-castle-fips`; the latter names are resolved through
Nimbus' provider singletons. JWE `encrypt` and `decrypt` accept the same
options, plus `:key-encryption-provider`, `:content-encryption-provider`, and
`:mac-provider` when those cryptographic operations need separate providers.

JWS signing also accepts `:allow-weak-rsa-key?` and
`:user-authentication-required?` where Nimbus' signer constructors support
those options. JWE encryption accepts `:cipher-mode` (`:wrap-unwrap` or
`:encrypt-decrypt`), and JWE decryption accepts that option,
`:allow-weak-rsa-key?`, and `:max-compressed-length`. The latter bounds the
compressed ciphertext length Nimbus will expand while processing a `:zip`
JWE; set it explicitly when the default limit is not appropriate.

The provider options make FIPS and hardware-provider deployments possible
without changing the process-wide JCA provider order. The FIPS singleton is
optional; if its classes are unavailable, jose-clj reports
`:missing-optional-dep`.

When `:user-authentication-required? true` is supplied to JWS signing with an
RSA or EC key, jose-clj returns a deferred-signing map containing the
initialized `java.security.Signature` and a `:complete` function. The caller
may authenticate through its environment and invoke `:complete` to obtain the
finished compact JWS. Nimbus' `RSASSASigner` and `ECDSASigner` implement this
through anonymous `CompletableJWSObjectSigning` classes; Nimbus signals the
pause with `ActionRequiredForJWSCompletionException` and the completion object
produces the signature.
