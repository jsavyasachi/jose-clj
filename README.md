# jose-clj

[![Clojars Project](https://img.shields.io/clojars/v/net.clojars.savya/jose-clj.svg)](https://clojars.org/net.clojars.savya/jose-clj)
[![cljdoc](https://cljdoc.org/badge/net.clojars.savya/jose-clj)](https://cljdoc.org/d/net.clojars.savya/jose-clj/CURRENT)
[![test](https://github.com/jsavyasachi/jose-clj/actions/workflows/test.yml/badge.svg)](https://github.com/jsavyasachi/jose-clj/actions/workflows/test.yml)

Idiomatic Clojure JOSE - JWS, JWE, JWK/JWKS, and JWT (signed, encrypted, and
nested) - over [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt),
the canonical Java JOSE implementation. It takes maps and returns maps.

## Stack

<a href="https://clojure.org"><img src="https://img.shields.io/badge/Clojure-5881D8?style=flat&logo=clojure&logoColor=fff" alt="Clojure" /></a>
<a href="https://connect2id.com/products/nimbus-jose-jwt"><img src="https://img.shields.io/badge/Nimbus%20JOSE+JWT-2D3748?style=flat" alt="Nimbus JOSE+JWT" /></a>

> Unofficial, community-maintained. Wraps Nimbus JOSE+JWT; not affiliated with
> Connect2id.

## Why

Clojure has only partial JOSE support. buddy-sign covers JWS and signed JWTs
well, but its JWE support is limited and it has been inactive since 2024. Other
libraries do JWT validation or remote JWKS retrieval, but not encryption or key
generation. No single library covered the whole of JOSE: full JWE, the JWK
lifecycle (generate, thumbprint, sets), cached remote JWKS, and modern
algorithms (EdDSA, ECDH-ES). jose-clj wraps the maintained Nimbus engine rather
than reimplementing cryptography. The cryptographic primitives are as correct as
Nimbus, and they stay correct as Nimbus is updated.

## Installation

deps.edn:

```clojure
net.clojars.savya/jose-clj {:mvn/version "0.6.1"}
```

Leiningen:

```clojure
[net.clojars.savya/jose-clj "0.6.1"]
```

Tracks `com.nimbusds/nimbus-jose-jwt` 10.9.1. jose-clj is a thin wrapper, so you
get Nimbus updates, including security fixes, when you bump that one dependency.
The weekly antq workflow proposes bumps automatically.

JDK 11+. Some paths need an optional engine on the classpath:

- EdDSA/Ed25519 needs `com.google.crypto.tink/tink`.
- ES256K (secp256k1) needs BouncyCastle (`org.bouncycastle/bcprov-jdk18on`).
- PEM parsing needs `org.bouncycastle/bcpkix-jdk18on`.

Everything else runs on the plain JDK. If you call one of these paths without
the engine, the error is `{:jose/error :missing-optional-dep}` and not a
`NoClassDefFoundError`.

## Usage

```clojure
(require '[jose.jwk :as jwk]
         '[jose.jwt :as jwt]
         '[jose.jwe :as jwe])

;; a signing key
(def k (jwk/generate :rsa {:kid "sig-1" :use :sig}))

;; signed JWT with claims and an expiry
(def token (jwt/sign k {:sub "alice" :iss "me"} {:expires-in 3600}))
(jwt/verify k token {:iss "me"})
;; => {:sub "alice" :iss "me" :exp 1751...}

;; JWE round trip (ECDH-ES key agreement + A256GCM)
(def ek (jwk/generate :ec {:curve :p-256}))
(def ct (jwe/encrypt ek "secret msg" {:alg :ecdh-es :enc :a256gcm}))
(:payload (jwe/decrypt ek ct))
;; => "secret msg"

(jwk/thumbprint k)   ;; => RFC 7638 SHA-256 thumbprint string
```

### Keys (`jose.jwk`)

```clojure
(jwk/generate :rsa {:size 2048 :kid "k1" :use :sig :alg :rs256})
(jwk/generate :ec  {:curve :p-256})       ; :p-256 :p-384 :p-521 :secp256k1
(jwk/generate :okp {:curve :ed25519})     ; :ed25519 (sign) :x25519 (encrypt)
(jwk/generate :oct {:size 256})           ; symmetric

(jwk/public-jwk k)      ; public-only counterpart (nil for :oct)
(jwk/->map k)           ; JWK as a Clojure map (includes private params)
(jwk/->json k {:private? false})
(jwk/thumbprint k)      ; RFC 7638
(jwk/key-type k)        ; :rsa :ec :okp :oct

;; JWK sets
(def ks (jwk/jwk-set [k1 k2]))
(jwk/find-key ks "k1")
(jwk/set->json ks)      ; public-only by default
```

### PEM keys (`jose.pem`)

```clojure
(require '[jose.pem :as pem])

(def private-pem (pem/jwk->pem k {:private? true})) ; PKCS#8 PRIVATE KEY
(def public-pem  (pem/jwk->pem k))                  ; SPKI PUBLIC KEY

(pem/pem->jwk private-pem) ; => JWK map
(pem/pem->jwk public-pem)  ; => public JWK map
```

`pem->jwk` accepts PEM public keys, private keys, and X.509 certificates. Nimbus
uses BouncyCastle PKIX to parse PEM. Add
`org.bouncycastle/bcpkix-jdk18on` at runtime when you parse PEM. EC private-key
export includes the matching public PEM block, so Nimbus can rebuild the full EC
JWK from PKCS#8 private material.

### Signing (`jose.jws`)

```clojure
(jws/sign k "payload")                 ; alg defaults per key type
(jws/sign k "payload" {:alg :rs256 :kid "k1" :headers {:cty "example"}})
(jws/verify k compact)                 ; => {:payload .. :payload-bytes .. :header ..}
(jws/header compact)                   ; unverified header
```

### Detached / unencoded JWS

```clojure
(def detached (jws/sign k "payload" {:detached? true}))
(jws/verify-detached k detached "payload")

(def unencoded (jws/sign k "payload" {:b64? false}))
(jws/verify k unencoded)

(def detached-unencoded
  (jws/sign k "$.02" {:detached? true :b64? false}))
(jws/verify-detached k detached-unencoded "$.02")
```

`:detached? true` serializes compact JWS as `header..signature`.
`:b64? false` sets RFC 7797 `b64:false` and marks `b64` critical. An attached
compact unencoded payload cannot contain `.`, because `.` is the compact JWS
delimiter. Use detached unencoded JWS for arbitrary payload bytes.

### Encryption (`jose.jwe`)

Full algorithm matrix: `:rsa-oaep-256/384/512`, `:ecdh-es` and `:ecdh-1pu`
(each with `+a128/192/256kw` variants), `:pbes2-hs256+a128kw`,
`:pbes2-hs384+a192kw`, `:pbes2-hs512+a256kw`, `:a128/192/256kw`,
`:a128/192/256gcmkw`, and `:dir`; encryption methods
`:a128/192/256cbc-hs256/384/512`, `:a128/192/256gcm`, and `:xc20p`. jose-clj
does not offer insecure RSA1_5.

```clojure
(jwe/encrypt k "payload" {:alg :rsa-oaep-256 :enc :a256gcm})
(jwe/decrypt k compact)                ; => {:payload .. :payload-bytes .. :header ..}
```

### JSON serialization

Compact serialization remains the default for `sign` and `encrypt`. The JSON APIs
support flattened serialization for one signature or recipient, and general
serialization for multiple signatures or recipients:

```clojure
(def signed-json
  (jws/sign-json k "payload" {:serialization :flattened}))
(jws/verify-json k signed-json {:algs #{:rs256}})

(def encrypted-json
  (jwe/encrypt-json [(jwk/public-jwk recipient-1)
                     (jwk/public-jwk recipient-2)]
                    "payload"
                    {:serialization :general
                     :alg :rsa-oaep-256
                     :enc :a256gcm}))
(jwe/decrypt-json recipient-1 encrypted-json)
```

`sign-json` accepts per-signature protected and unprotected headers in general
form. `encrypt-json` accepts shared protected and unprotected headers; general JWE
places key-management data on each recipient.

### JWTs (`jose.jwt`)

```clojure
(jwt/sign k {:sub "alice"} {:expires-in 3600 :now-iat? true})
(jwt/verify k token {:iss "me" :aud "you" :clock-skew 60 :required [:sub]})
;; validation failures throw ex-info: :expired :not-yet-valid
;; :claim-mismatch :missing-claim :invalid-signature

;; encrypted JWT
(jwt/encrypt ek {:sub "alice"} {:alg :ecdh-es :enc :a256gcm})
(jwt/decrypt ek token)

;; nested: sign then encrypt, decrypt then verify
(jwt/sign-then-encrypt sign-key enc-key {:sub "alice"})
(jwt/decrypt-then-verify enc-key sign-key token {:iss "me"})
```

### Remote JWKS (`jose.jwks`)

```clojure
(require '[jose.jwks :as jwks])

;; cached remote source (defaults shown are Nimbus defaults; all optional)
(def src (jwks/remote-source "https://www.googleapis.com/oauth2/v3/certs"
                             {:cache-ttl-ms 300000 :connect-timeout-ms 5000}))

;; HTTPS is required by default; use :https-only? false only for a trusted
;; non-TLS endpoint. :read-timeout-ms and :http-size-limit tune HTTP fetching.

(jwks/get-keys src {:use :sig :kty :rsa})  ; matched keys
(jwks/find-key src "kid-123")

;; verify a token against the source: the key is picked by the token's kid and
;; alg, and the verifier is chosen from the key type - so an HS256 forgery over
;; an RSA public key is rejected, not confused for a valid MAC
(jws/verify-with-jwks src compact)
(jwt/verify-with-jwks src token {:iss "https://accounts.google.com"})
```

### Key rotation and public JWKS (`jose.keyring`)

```clojure
(require '[jose.keyring :as keyring])

(def ring
  (keyring/key-ring [signing-key encryption-key]
                    {:active-signing-kid "sig-1"
                     :active-encryption-kid "enc-1"}))

(def token (keyring/sign ring "payload"))
(keyring/verify ring token {:algs #{:rs256}})

(def rotated (keyring/rotate ring :signing next-signing-key))
(def pruned (keyring/prune rotated {:retention-seconds 86400}))

(keyring/public-jwks rotated)       ; Nimbus JWKSet
(keyring/public-jwks-json rotated)  ; publication-ready JWKS JSON
```

The immutable key ring keeps the active signing and encryption keys. Retained
keys continue to verify or decrypt older messages. A published JWKS contains
only public key material: jose-clj removes private parameters and omits
symmetric keys.

## Errors

Bad input does not cause a `NullPointerException`. API and parse failures
normalize to `ex-info` with a `:jose/error` key and the original exception as
the cause:

| `:jose/error` | when |
|---|---|
| `:invalid-option` | unknown option keyword |
| `:parse-failure` | malformed JWK / JWS / JWE / JWKS |
| `:invalid-signature` / `:sign-failure` | JWS/JWT signature does not verify / signing failed |
| `:encryption-failure` / `:decryption-failure` | JWE will not encrypt / decrypt with the given key |
| `:expired` / `:not-yet-valid` | `exp` / `nbf` claim checks (with `:clock-skew`) |
| `:claim-mismatch` / `:missing-claim` | `:aud` / `:iss` / `:required` checks |
| `:key-not-found` / `:ambiguous-key` | JWKS key selection |
| `:not-a-nested-jwt` | `decrypt-then-verify` on a JWE whose payload is not a JWT |
| `:key-source-failure` | remote JWKS fetch failed |
| `:key-length` | symmetric key wrong size for the algorithm |
| `:missing-optional-dep` | optional Tink/BouncyCastle path without its runtime dependency |
| `:invalid-url` | bad JWKS URL |

## License

Copyright © 2026 Savyasachi

Distributed under the [Eclipse Public License 2.0](https://www.eclipse.org/legal/epl-2.0/).
