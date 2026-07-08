# Migrating from buddy-sign

buddy-sign is solid for JWS and signed JWT use cases and remains fine for those.
jose-clj is useful when a project needs full JWE support, a JWK lifecycle,
cached remote JWKS verification, or modern algorithms such as EdDSA and ECDH-ES.

Factually, buddy-sign has been dormant since 2024.

## Function mapping

| buddy-sign / buddy-core pattern | jose-clj equivalent |
|---|---|
| `buddy-sign.jwt/sign` | `jose.jwt/sign` |
| `buddy-sign.jwt/unsign` | `jose.jwt/verify` |
| Parse JWT claims without verification | `jose.jwt/claims` |
| `buddy-sign.jws/sign` | `jose.jws/sign` |
| `buddy-sign.jws/unsign` | `jose.jws/verify` |
| `buddy-sign.jwe/encrypt` | `jose.jwe/encrypt` for payloads, or `jose.jwt/encrypt` for JWT claims |
| `buddy-sign.jwe/decrypt` | `jose.jwe/decrypt` for payloads, or `jose.jwt/decrypt` for JWT claims |
| Local key collection | `jose.jwk/jwk-set` plus `jose.jwks/local-source` |
| Remote JWKS verification | `jose.jwks/remote-source` plus `jose.jws/verify-with-jwks` or `jose.jwt/verify-with-jwks` |
| `buddy-core.keys/public-key` or `buddy-core.keys/private-key` from PEM | `jose.jwk/parse` of a JWK. jose-clj is JWK-centric and does not expose a PEM loader in `src/`. Convert PEM to JWK with Nimbus JOSE+JWT when needed, then pass the JWK JSON, map, or Nimbus JWK to jose-clj. |

## JWKs instead of raw Java keys

buddy-based code often passes raw `java.security` keys from buddy-core key
loading helpers. jose-clj APIs take JWK input:

```clojure
(require '[jose.jwk :as jwk]
         '[jose.jwt :as jwt])

(def key
  (jwk/generate :rsa {:kid "sig-1" :use :sig :alg :rs256}))

(def token
  (jwt/sign key {:sub "alice"} {:expires-in 3600}))

(jwt/verify key token {:required [:sub]})
```

`jwk/parse` accepts JWK JSON strings, Clojure maps, or Nimbus JWK values. `jwk/->json`
and `jwk/->map` serialize keys. `jwk/public-jwk` returns the public form for
asymmetric keys and `nil` for `:oct`.

## Options

buddy-sign APIs commonly use raw Java keys and option maps around the chosen
operation. jose-clj uses JWKs plus keyword algorithm names.

Examples:

| Need | jose-clj option |
|---|---|
| RSA signed JWT | `jwt/sign` with `{:alg :rs256}` |
| RSA-PSS signed JWT | `jwt/sign` with `{:alg :ps256}` |
| ECDSA signed JWT | `jwt/sign` with `{:alg :es256}` |
| EdDSA signed JWT | `jwt/sign` with `{:alg :eddsa}` and an OKP `:ed25519` JWK |
| JWE ECDH-ES with AES-GCM | `jwt/encrypt` or `jwe/encrypt` with `{:alg :ecdh-es :enc :a256gcm}` |
| Header key ID | `:kid` on `jwt/sign`, `jws/sign`, `jwt/encrypt`, or `jwe/encrypt` |
| Extra protected headers | `:headers` |

## Claim validation

buddy-sign signed JWT flows usually combine signing or unsigning with claims such
as expiration, not-before, audience, and issuer. In jose-clj:

| Claim behavior | jose-clj API |
|---|---|
| Add expiration at sign time | `jwt/sign` or `jwt/encrypt` with `{:expires-in seconds}` |
| Add issued-at at sign time | `jwt/sign` or `jwt/encrypt` with `{:now-iat? true}` |
| Provide explicit `:exp`, `:nbf`, or `:iat` | Put `java.time.Instant` or epoch seconds in the claims map. |
| Validate expiration | `jwt/verify`, `jwt/decrypt`, or `jwt/verify-with-jwks` checks `:exp` automatically when present. |
| Validate not-before | `jwt/verify`, `jwt/decrypt`, or `jwt/verify-with-jwks` checks `:nbf` automatically when present. |
| Allow clock skew | Verify with `{:clock-skew seconds}`. |
| Validate audience | Verify with `{:aud "expected-audience"}`. |
| Validate issuer | Verify with `{:iss "expected-issuer"}`. |
| Require claims | Verify with `{:required [:sub :iss]}`. |

Relevant jose-clj validation error keywords are `:expired`, `:not-yet-valid`,
`:claim-mismatch`, `:missing-claim`, and `:invalid-signature`.

## JWS payloads

For non-JWT JWS payloads:

```clojure
(require '[jose.jws :as jws])

(def compact
  (jws/sign key "payload" {:alg :rs256 :kid "sig-1"}))

(jws/verify key compact)
;; => {:payload "payload", :payload-bytes ..., :header ...}
```

`jws/sign` accepts string or byte-array payloads. `jws/verify` returns both the
UTF-8 string payload and raw bytes.

## JWE payloads

For non-JWT encrypted payloads:

```clojure
(require '[jose.jwe :as jwe])

(def encryption-key
  (jwk/generate :ec {:curve :p-256 :kid "enc-1" :use :enc}))

(def ciphertext
  (jwe/encrypt encryption-key "secret msg" {:alg :ecdh-es :enc :a256gcm}))

(jwe/decrypt encryption-key ciphertext)
;; => {:payload "secret msg", :payload-bytes ..., :header ...}
```

For JWT claims, prefer `jwt/encrypt` and `jwt/decrypt`.
