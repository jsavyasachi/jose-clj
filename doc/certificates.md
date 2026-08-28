# Certificates, JCA keys, and key stores

`jose.pem` handles certificate chains as well as individual PEM keys. A PEM
chain can be parsed into `X509Certificate` values or converted directly to the
Base64 strings used by a JWK `:x5c` member:

```clojure
(def certificates (pem/pem->certificates pem-text))
(def x5c (pem/pem->x5c pem-text))
(def pem-again (pem/certificates->pem certificates))
```

The file arity of `pem->certificates` accepts a `java.io.File`. Chain order is
preserved. `pem/x5c->certificates` is the inverse of `pem->x5c`.

JWK certificate metadata can be inspected in either form. `jwk/x509-cert-chain`
returns the raw Base64 values, while `jwk/x509-certificates` returns parsed
`X509Certificate` objects.

For JCA interoperability, `jwk/to-java-keys` converts one JWK or a collection
of JWK inputs to a vector of Java keys. `jwk/to-java-private-key` explicitly
selects the private key from a private JWK. Inputs follow `jwk/parse`: maps,
JSON strings, and Nimbus JWK values are accepted.

To load every key entry in a key store, use `jwk/keystore->jwks` with either a
map of alias to password or a password lookup function:

```clojure
(jwk/keystore->jwks keystore {"signing" "signing-pin"
                               "encryption" "encryption-pin"})
```

The existing `jwk/keystore->jwk` remains available for loading one alias with
one PIN.
