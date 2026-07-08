# Getting Started

## Install

deps.edn:

```clojure
net.clojars.savya/jose-clj {:mvn/version "0.1.1"}
```

Leiningen:

```clojure
[net.clojars.savya/jose-clj "0.1.1"]
```

jose-clj requires JDK 11 or newer.

Most algorithms run on the plain JDK. Two paths need optional dependencies:

```clojure
;; EdDSA / Ed25519
com.google.crypto.tink/tink {:mvn/version "1.18.0"}

;; ES256K / secp256k1
org.bouncycastle/bcprov-jdk18on {:mvn/version "1.80"}
```

If an EdDSA or ES256K path is used without its optional engine, jose-clj throws
`ex-info` with `{:jose/error :missing-optional-dep}`.

## Namespaces

| Namespace | Purpose |
|---|---|
| `jose.jwk` | Generate, parse, serialize, inspect, and group JWKs. |
| `jose.jws` | Sign and verify compact JWS payloads. |
| `jose.jwe` | Encrypt and decrypt compact JWE payloads. |
| `jose.jwt` | Sign, verify, encrypt, decrypt, and nest JWT claims. |
| `jose.jwks` | Build local or remote JWKS sources and select keys. |

## First signed JWT

```clojure
(require '[jose.jwk :as jwk]
         '[jose.jwt :as jwt])

(def signing-key
  (jwk/generate :rsa {:kid "sig-1" :use :sig :alg :rs256}))

(def token
  (jwt/sign signing-key
            {:sub "alice" :iss "me"}
            {:expires-in 3600 :now-iat? true}))

(jwt/verify signing-key token {:iss "me" :required [:sub]})
;; => {:sub "alice"
;;     :iss "me"
;;     :iat #object[java.time.Instant ...]
;;     :exp #object[java.time.Instant ...]}

(jwt/claims token)
;; => unverified claims map
```

`jwt/sign` accepts a claims map. Registered time claims `:exp`, `:nbf`, and
`:iat` can be `java.time.Instant` values or epoch seconds. `:expires-in` adds an
`:exp` claim relative to now. `:now-iat? true` adds an `:iat` claim.

## First JWE

```clojure
(require '[jose.jwk :as jwk]
         '[jose.jwe :as jwe])

(def encryption-key
  (jwk/generate :ec {:curve :p-256 :kid "enc-1" :use :enc}))

(def ciphertext
  (jwe/encrypt encryption-key
               "secret msg"
               {:alg :ecdh-es :enc :a256gcm}))

(:payload (jwe/decrypt encryption-key ciphertext))
;; => "secret msg"
```

## Error contract

Bad input is normalized to `ex-info`, not `NullPointerException`. jose-clj puts
the machine-readable keyword under `:jose/error` in `ex-data`, and keeps the
underlying Java or Nimbus exception as `ex-cause` when one exists.

The README has the error table covering parse failures, invalid options,
signature failures, JWE failures, JWT claim validation, JWKS key selection,
optional dependency failures, and URL failures.
