# JWT: Signed, Encrypted, Nested

All operations in `jose.jwt` are local. `jwt/sign`, `jwt/verify`,
`jwt/encrypt`, `jwt/decrypt`, `jwt/sign-then-encrypt`, `jwt/decrypt-then-verify`,
and `jwt/claims` do not perform network I/O.

```clojure
(require '[jose.jwk :as jwk]
         '[jose.jwt :as jwt])
```

## Signed JWTs

```clojure
(def signing-key
  (jwk/generate :rsa {:kid "sig-1" :use :sig :alg :rs256}))

(def token
  (jwt/sign signing-key
            {:sub "alice"
             :iss "https://issuer.example"
             :aud "api"}
            {:expires-in 3600
             :now-iat? true}))
```

`jwt/sign` takes a JWK, a claims map, and optional signing options.

Signing options:

| Option | Meaning |
|---|---|
| `:alg` | JWS algorithm keyword, string, or Nimbus `JWSAlgorithm`. Defaults from key type and curve. |
| `:kid` | Header key ID. Defaults to the JWK key ID when present. |
| `:headers` | Extra protected header map. `:typ` and `:cty` are handled as registered header fields. |
| `:expires-in` | Seconds from now used to add or replace `:exp`. |
| `:now-iat?` | When true, adds or replaces `:iat` with the current time. |

Registered time claims `:exp`, `:nbf`, and `:iat` accept `java.time.Instant` or
epoch seconds.

```clojure
(jwt/verify signing-key token
            {:iss "https://issuer.example"
             :aud "api"
             :clock-skew 60
             :required [:sub]})
;; => verified claims map
```

`jwt/verify` verifies the signature and validates requested claims.

Verify options:

| Option | Meaning |
|---|---|
| `:iss` | Expected issuer. |
| `:aud` | Expected audience value. |
| `:clock-skew` | Allowed clock skew in seconds for `:exp` and `:nbf`. Defaults to `0`. |
| `:required` | Required claim keys. Missing claims fail validation. |

JWT claim validation error keywords:

| `:jose/error` | Cause |
|---|---|
| `:expired` | `:exp` is before now, after applying `:clock-skew`. |
| `:not-yet-valid` | `:nbf` is after now, after applying `:clock-skew`. |
| `:claim-mismatch` | `:iss` or `:aud` does not match the verify options. |
| `:missing-claim` | A claim listed in `:required` is absent. |
| `:invalid-signature` | The compact JWT signature does not verify with the supplied key. |

`jwt/claims` parses a compact signed JWT and returns its claims without verifying
the signature:

```clojure
(jwt/claims token)
;; => unverified claims map
```

Registered claims are keyword keys. Custom claims keep their string keys.
`:exp`, `:nbf`, and `:iat` return `java.time.Instant` values. `:aud` returns a
vector.

## Encrypted JWTs

```clojure
(def encryption-key
  (jwk/generate :ec {:curve :p-256 :kid "enc-1" :use :enc}))

(def encrypted-token
  (jwt/encrypt encryption-key
               {:sub "alice" :iss "https://issuer.example"}
               {:alg :ecdh-es :enc :a256gcm}))

(jwt/decrypt encryption-key encrypted-token)
;; => decrypted and validated claims map
```

`jwt/encrypt` accepts the JWE options `:alg`, `:enc`, `:kid`, and `:headers`,
plus the JWT time options `:expires-in` and `:now-iat?`.

`jwt/decrypt` decrypts the JWE payload and validates claims with the same verify
options as `jwt/verify`: `:iss`, `:aud`, `:clock-skew`, and `:required`.

## Nested JWTs

Nested JWTs are signed first, then encrypted. The encrypted JWE carries
`{:cty "JWT"}` in its headers.

```clojure
(def nested-token
  (jwt/sign-then-encrypt signing-key
                         encryption-key
                         {:sub "alice"
                          :iss "https://issuer.example"}
                         {:sign-opts {:alg :rs256
                                      :expires-in 3600}
                          :encrypt-opts {:alg :ecdh-es
                                         :enc :a256gcm}}))

(jwt/decrypt-then-verify encryption-key
                         signing-key
                         nested-token
                         {:iss "https://issuer.example"
                          :required [:sub]})
;; => verified claims map
```

`jwt/decrypt-then-verify` throws `ex-info` with
`{:jose/error :not-a-nested-jwt}` when the decrypted JWE payload is not a compact
signed JWT.
