# Verifying with Remote JWKS

`jose.jwks` wraps Nimbus key sources. A source can be remote and cached, or local
and in-memory.

```clojure
(require '[jose.jwk :as jwk]
         '[jose.jwks :as jwks]
         '[jose.jws :as jws]
         '[jose.jwt :as jwt])
```

## Remote sources

```clojure
(def source
  (jwks/remote-source "https://www.googleapis.com/oauth2/v3/certs"
                      {:cache-ttl-ms 300000
                       :cache-refresh-ms 15000
                       :connect-timeout-ms 5000
                       :read-timeout-ms 5000
                       :rate-limit-ms 30000}))
```

Options:

| Option | Meaning |
|---|---|
| `:cache-ttl-ms` | Cache time to live in milliseconds. |
| `:cache-refresh-ms` | Cache refresh timeout in milliseconds. |
| `:connect-timeout-ms` | HTTP connect timeout in milliseconds. |
| `:read-timeout-ms` | HTTP read timeout in milliseconds. |
| `:rate-limit-ms` | Minimum interval for Nimbus rate limiting. |

All options are optional. Without options, Nimbus defaults are used. The remote
source built by Nimbus already caches keys.

Invalid URLs throw `ex-info` with `{:jose/error :invalid-url}`. Remote retrieval
failures from `jwks/get-keys` throw `{:jose/error :key-source-failure}`.

## Local sources

```clojure
(def rsa-key
  (jwk/generate :rsa {:kid "rsa-1" :use :sig :alg :rs256}))

(def local
  (jwks/local-source [(jwk/public-jwk rsa-key)]))
```

`jwks/local-source` accepts a vector of JWKs or a JWK set value accepted by
`jwk/parse-set`.

## Selecting keys

```clojure
(jwks/get-keys local {:kid "rsa-1"})
(jwks/get-keys local {:kty :rsa :use :sig :alg :rs256})
(jwks/find-key local "rsa-1")
```

Matcher options for `jwks/get-keys`:

| Option | Values |
|---|---|
| `:kid` | Key ID string. |
| `:kty` | `:rsa`, `:ec`, `:okp`, or `:oct`. |
| `:use` | `:sig` or `:enc`. |
| `:alg` | Algorithm keyword, string, or Nimbus `Algorithm`. |

`jwks/get-keys` returns a vector. `jwks/find-key` returns the first matching key
for a key ID, or `nil`.

## Verifying JWS or JWT

```clojure
(def compact-jws
  (jws/sign rsa-key "payload" {:alg :rs256 :kid "rsa-1"}))

(jws/verify-with-jwks local compact-jws)
;; => {:payload "payload", :payload-bytes ..., :header ...}

(def compact-jwt
  (jwt/sign rsa-key
            {:sub "alice" :iss "https://issuer.example"}
            {:alg :rs256 :kid "rsa-1" :expires-in 3600}))

(jwt/verify-with-jwks local compact-jwt {:iss "https://issuer.example"})
;; => verified claims map
```

`jws/verify-with-jwks` and `jwt/verify-with-jwks` select a key with the compact
object header `kid` and `alg`, then call the normal verifier.

Key selection errors:

| `:jose/error` | Cause |
|---|---|
| `:key-not-found` | No key matches the header `kid` and `alg`. |
| `:ambiguous-key` | The compact object has no `kid` and more than one key matches `alg`. |

The verifier is chosen by the selected JWK key type, not by trusting the compact
object algorithm alone. An HS256 forgery over an RSA public key is rejected
because the selected RSA JWK is verified with an RSA verifier, not a MAC
verifier.

## Integration tests

The repository includes a `^:integration` test that reads Google's certificate
JWKS:

```clojure
(jwks/remote-source "https://www.googleapis.com/oauth2/v3/certs")
```

It is skipped by default through `tests.edn`:

```clojure
:skip-meta [:integration]
```

Use remote-source examples as illustrative unless the test environment allows
network access.
