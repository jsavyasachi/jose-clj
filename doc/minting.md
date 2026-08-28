# Minting JWS

`jose.mint` wraps Nimbus JWS minting. A minter signs a payload after selecting
the signing JWK from a JWKS source using the requested JWS header `alg` and
optional `kid`.

Use minting when key selection belongs to the source rather than the caller:

```clojure
(require '[jose.jwk :as jwk]
         '[jose.jwks :as jwks]
         '[jose.mint :as mint]
         '[jose.jws :as jws])

(def signing-key
  (jwk/generate :rsa {:kid "signing-2026" :use :sig :alg :rs256}))
(def source (jwks/local-source [signing-key]))
(def minter (mint/minter source))

(def compact
  (mint/mint minter "hello"
             {:alg :rs256 :kid "signing-2026" :typ "JWT"}))

(jws/verify-with-jwks source compact {:alg :rs256})
;; => {:payload "hello", :payload-bytes ..., :header ...}
```

`mint/minter` also accepts a Nimbus `JWKSource`, `JWKSet`, or a vector of JWK
maps. Pass `:signer-factory` when Nimbus signer construction needs custom
configuration; otherwise it uses `DefaultJWSSignerFactory`.

Reach for `jose.keyring` when the application has an explicit active signing
key and wants a small immutable rotation policy with retained old keys. Reach
for `jose.mint` when Nimbus should select a key from the source for each header.
The two approaches are complementary: a key ring can manage rotation, while a
minter can perform native source-based selection.
