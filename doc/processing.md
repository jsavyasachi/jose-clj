# Generic JOSE processing

Use `jose.proc` when the payload is an arbitrary string or byte sequence rather
than a JWT claims set. Use `jose.jwt` when you need JWT claims validation,
nested JWT handling, or the JWT convenience functions.

Build a processor with a JWKS source and explicit algorithm policies. JWS
algorithms are supplied as `:jws-algs` (or singular `:jws-alg`), JWE key
management algorithms as `:jwe-algs`, and content-encryption methods as
`:jwe-encs`. `:typ` optionally requires an exact JOSE type. Plain unsecured
objects are rejected.

```clojure
(require '[jose.jwk :as jwk]
         '[jose.jwks :as jwks]
         '[jose.proc :as proc])

(let [key (jwk/generate :oct {:size 256 :kid "signing-key"})
      source (jwks/local-source [key])
      processor (proc/processor source
                                 {:jws-algs #{:hs256}
                                  :jwe-algs #{:dir}
                                  :jwe-encs #{:a256gcm}})]
  (proc/process processor compact-serialization))
;; => {:payload "arbitrary payload", :payload-bytes ...}
```

For key selection derived from the keys in a source, use
`(proc/jws-key-selector :rsa source)` (or `:hmac-sha`, `:ec`, `:ed`, or
`:signature`) as `:jws-key-selector`. The selector can also be made directly
from a Nimbus source with `jws-key-selector`, or from a JWKS
URL with `jws-key-selector-from-jwk-set-url`. For one key, use
`single-key-selector`. A `security-context` can supply JWKs per call:
`(proc/process processor compact (proc/security-context [key]))`.

A key selector can only narrow the algorithms a processor accepts. When
`:jws-algs`, `:jwe-algs`, or `:jwe-encs` is also configured, the effective
allow-list is the intersection of the configuration and the selector, so an
`:rsa` family selector next to `:jws-algs #{:rs256}` still rejects `RS512`.
Omit the allow-list to let the selector alone decide.

To customize Nimbus's verification or decryption implementation, pass a
`JWSVerifierFactory` as `:jws-verifier-factory` or a `JWEDecrypterFactory` as
`:jwe-decrypter-factory`. Both default to Nimbus's
`DefaultJWSVerifierFactory` and `DefaultJWEDecrypterFactory`; their accessors
are `jws-verifier-factory` and `jwe-decrypter-factory`. These factories expose
JCA contexts for selecting a specific security provider. Supplying either
factory also marks that processing side as configured, but a key selector or
algorithm policy is still needed for successful processing.

`matcher` returns a predicate for JOSE objects or compact strings. Its
criteria are `:classes` (such as `:jws` or `:jwe`), `:algorithms`, `:encryption-methods`, `:jwk-urls`,
and `:key-ids`.

Nimbus 10.9.1 has an upstream limitation: `JWSVerificationKeySelector` does
not resolve EdDSA keys from a JWK source. Pass the key directly with a
single-key selector, or provide a custom `:jws-key-selector` when processing
EdDSA. This is also present in the library's existing JWT and JWS JWKS
helpers.
