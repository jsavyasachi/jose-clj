# Keys and JWK Sets

`jose.jwk` is JWK-centric. Functions accept Nimbus JWK values directly, JWK JSON
strings, or Clojure maps where documented.

```clojure
(require '[jose.jwk :as jwk])
```

## Generate keys

`jwk/generate` takes a key type and an option map.

```clojure
;; RSA: :size plus common :kid, :use, :alg
(def rsa-key
  (jwk/generate :rsa {:size 2048 :kid "rsa-1" :use :sig :alg :rs256}))

;; EC: :curve plus common :kid, :use, :alg
(def ec-key
  (jwk/generate :ec {:curve :p-256 :kid "ec-1" :use :enc}))

;; OKP: :curve plus common :kid, :use, :alg
(def okp-key
  (jwk/generate :okp {:curve :ed25519 :kid "okp-1" :use :sig :alg :eddsa}))

;; OCT: :size plus common :kid, :use, :alg
(def oct-key
  (jwk/generate :oct {:size 256 :kid "oct-1" :use :sig}))
```

Valid key types are `:rsa`, `:ec`, `:okp`, and `:oct`.

Common options:

| Option | Values |
|---|---|
| `:kid` | Key ID string, or `nil`. If omitted, jose-clj asks Nimbus to derive one from the thumbprint. |
| `:use` | `:sig` or `:enc`. |
| `:alg` | Keyword, string, or Nimbus `Algorithm`. Common keywords include `:rs256`, `:ps256`, `:es256`, `:es256k`, `:eddsa`, `:a128kw`, `:a192kw`, `:a256kw`, and `:dir`. |

Curve keywords:

| Key type | `:curve` values |
|---|---|
| `:ec` | `:p-256`, `:p-384`, `:p-521`, `:secp256k1` |
| `:okp` | `:ed25519`, `:x25519` |

`:okp` / `:ed25519` requires `com.google.crypto.tink/tink` when the key is used
for EdDSA. `:ec` / `:secp256k1` requires `org.bouncycastle/bcprov-jdk18on` when
the key is used for ES256K. Without the optional dependency, the error keyword is
`:missing-optional-dep`.

## Inspect and serialize

```clojure
(jwk/key-type rsa-key)
;; => :rsa

(jwk/key-id rsa-key)
;; => "rsa-1"

(jwk/private? rsa-key)
;; => true

(jwk/thumbprint rsa-key)
;; => RFC 7638 SHA-256 thumbprint string

(def public-rsa-key (jwk/public-jwk rsa-key))
;; => public-only Nimbus JWK

(jwk/public-jwk oct-key)
;; => nil
```

`jwk/->map` returns the complete JWK JSON representation as a Clojure map,
including private parameters when present:

```clojure
(jwk/->map rsa-key)
```

`jwk/->json` returns JSON. By default it includes private parameters. Pass
`{:private? false}` to serialize the public form:

```clojure
(jwk/->json rsa-key)
(jwk/->json rsa-key {:private? false})
```

For `:oct` keys, `jwk/->json` with `{:private? false}` returns `nil` because a
symmetric key has no public form.

## Parse keys

`jwk/parse` accepts a JWK JSON string, a Clojure map, or a Nimbus JWK. Nimbus JWK
input is returned unchanged.

```clojure
(def parsed-from-json (jwk/parse (jwk/->json rsa-key)))
(def parsed-from-map  (jwk/parse (jwk/->map rsa-key)))
(def same-key         (jwk/parse rsa-key))
```

Malformed input throws `ex-info` with `{:jose/error :parse-failure}`.

## JWK sets

```clojure
(def key-set
  (jwk/jwk-set [rsa-key ec-key]))

(jwk/find-key key-set "rsa-1")
;; => rsa-key

(jwk/set->maps key-set)
;; => vector of complete JWK maps

(jwk/set->json key-set)
;; => public-only JWKS JSON by default

(jwk/set->json key-set {:private? true})
;; => JWKS JSON including private parameters
```

`jwk/parse-set` accepts a JWKS JSON string, a Clojure map, or a Nimbus `JWKSet`.
Nimbus `JWKSet` input is returned unchanged.

`jwk/set->json` defaults to `{:private? false}` so public-only output is the
default for sets.
