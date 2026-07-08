# jose-clj

[![Clojars Project](https://img.shields.io/clojars/v/net.clojars.savya/jose-clj.svg)](https://clojars.org/net.clojars.savya/jose-clj)
[![cljdoc](https://cljdoc.org/badge/net.clojars.savya/jose-clj)](https://cljdoc.org/d/net.clojars.savya/jose-clj/CURRENT)
[![test](https://github.com/jsavyasachi/jose-clj/actions/workflows/test.yml/badge.svg)](https://github.com/jsavyasachi/jose-clj/actions/workflows/test.yml)

Idiomatic Clojure JOSE - JWS, JWE, JWK/JWKS, and JWT (signed, encrypted, and
nested) - over [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt),
the canonical Java JOSE implementation. Maps in, maps out.

## Stack

<a href="https://clojure.org"><img src="https://img.shields.io/badge/Clojure-5881D8?style=flat&logo=clojure&logoColor=fff" alt="Clojure" /></a>
<a href="https://connect2id.com/products/nimbus-jose-jwt"><img src="https://img.shields.io/badge/Nimbus%20JOSE+JWT-2D3748?style=flat" alt="Nimbus JOSE+JWT" /></a>

> Unofficial, community-maintained. Wraps Nimbus JOSE+JWT; not affiliated with
> Connect2id.

## Why

Clojure's JOSE story is partial. buddy-sign covers JWS and signed JWTs well but
its JWE support is limited and it has been dormant since 2024; other libraries do
JWT validation or remote JWKS fetching but not encryption or key generation. There
was no single, idiomatic library covering the whole of JOSE - in particular full
JWE, the JWK lifecycle (generate, thumbprint, sets), cached remote JWKS, and
modern algorithms (EdDSA, ECDH-ES). jose-clj wraps the maintained, complete Nimbus
engine rather than reimplementing any crypto, so the primitives are as correct as
Nimbus and stay correct as it is updated.

## Installation

deps.edn:

```clojure
net.clojars.savya/jose-clj {:mvn/version "0.1.1"}
```

Leiningen:

```clojure
[net.clojars.savya/jose-clj "0.1.1"]
```

Tracks `com.nimbusds/nimbus-jose-jwt` 10.9.1. Because jose-clj is a thin wrapper,
Nimbus updates (including security fixes) are picked up by bumping that one
dependency; the weekly antq workflow proposes bumps automatically.

JDK 11+. Two algorithms need an optional engine on the classpath: EdDSA/Ed25519
requires `com.google.crypto.tink/tink`, and ES256K (secp256k1) requires
BouncyCastle (`org.bouncycastle/bcprov-jdk18on`). Everything else runs on the
plain JDK. If you call an EdDSA or ES256K path without the engine present, the
error is `{:jose/error :missing-optional-dep}` rather than a `NoClassDefFoundError`.

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

### Signing (`jose.jws`)

```clojure
(jws/sign k "payload")                 ; alg defaults per key type
(jws/sign k "payload" {:alg :rs256 :kid "k1" :headers {:cty "example"}})
(jws/verify k compact)                 ; => {:payload .. :payload-bytes .. :header ..}
(jws/header compact)                   ; unverified header
```

### Encryption (`jose.jwe`)

Full algorithm matrix: `:rsa-oaep-256/384/512`, `:ecdh-es` (and `+a128/192/256kw`),
`:a128/192/256kw`, `:a128/192/256gcmkw`, `:dir`; encryption methods
`:a128/192/256cbc-hs256/384/512` and `:a128/192/256gcm`. The insecure RSA1_5 is
deliberately not offered.

```clojure
(jwe/encrypt k "payload" {:alg :rsa-oaep-256 :enc :a256gcm})
(jwe/decrypt k compact)                ; => {:payload .. :payload-bytes .. :header ..}
```

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

(jwks/get-keys src {:use :sig :kty :rsa})  ; matched keys
(jwks/find-key src "kid-123")

;; verify a token against the source: the key is picked by the token's kid and
;; alg, and the verifier is chosen from the key type - so an HS256 forgery over
;; an RSA public key is rejected, not confused for a valid MAC
(jws/verify-with-jwks src compact)
(jwt/verify-with-jwks src token {:iss "https://accounts.google.com"})
```

## Errors

Bad input never NPEs. API and parse failures normalize to `ex-info` with a
`:jose/error` key and the original exception as the cause:

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
| `:missing-optional-dep` | EdDSA/ES256K path without tink/BouncyCastle |
| `:invalid-url` | bad JWKS URL |

## License

Copyright © 2026 Savyasachi

Distributed under the [Eclipse Public License 2.0](https://www.eclipse.org/legal/epl-2.0/).
