(ns jose.proc-test
  (:require [clojure.test :refer [deftest is testing]]
            [jose.jwe :as jwe]
            [jose.jwk :as jwk]
            [jose.jwks :as jwks]
            [jose.jws :as jws]
            [jose.proc :as proc])
  (:import (clojure.lang ExceptionInfo)
           (com.nimbusds.jose JWEObject JWSAlgorithm JWSHeader JWSObject)
           (com.nimbusds.jose.jwk Curve JWK JWKSet)
           (com.nimbusds.jose.jwk.gen OctetKeyPairGenerator)
           (com.nimbusds.jose.jwk.source ImmutableJWKSet)
           (com.nimbusds.jose.proc JWSVerificationKeySelector SimpleSecurityContext)
           (java.net URI)))

(defn thrown-data [f]
  (try
    (f)
    nil
    (catch ExceptionInfo e
      (ex-data e))))

(defn policy [source]
  {:jws-algs #{:hs256} :jwe-algs #{:dir} :jwe-encs #{:a256gcm}})

(deftest processes-arbitrary-signed-payloads
  (let [key (jwk/generate :oct {:size 256 :kid "sig"})
        source (jwks/local-source [key])
        processor (proc/processor source (policy source))]
    (is (= "arbitrary text" (:payload (proc/process processor (jws/sign key "arbitrary text")))))
    (is (= "{\"not\":\"claims\"}"
           (:payload (proc/process processor (jws/sign key "{\"not\":\"claims\"}")))))))

(deftest processes-encrypted-payload
  (let [key (jwk/generate :oct {:size 256 :kid "enc"})
        source (jwks/local-source [key])
        processor (proc/processor source (policy source))
        compact (jwe/encrypt key "secret text" {:alg :dir})]
    (is (= "secret text" (:payload (proc/process processor compact))))))

(deftest processor-rejects-unsafe-or-mismatched-input
  (let [key (jwk/generate :oct {:size 512 :kid "sig"})
        source (jwks/local-source [key])
        processor (proc/processor source (assoc (policy source) :typ "JOSE"))
        plain "eyJhbGciOiJub25lIn0.cGxhaW4."
        disallowed (jws/sign key "payload" {:alg :hs384})
        typed (jws/sign key "payload" {:headers {:typ "JWT"}})]
    (is (= :unsecured-plain (:jose/error (thrown-data #(proc/process processor plain)))))
    (is (= :algorithm-not-allowed
           (:jose/error (thrown-data #(proc/process processor disallowed)))))
    (is (= :header-mismatch
           (:jose/error (thrown-data #(proc/process processor typed)))))))

(deftest algorithm-family-selector-derives-allowed-algorithms
  (let [key (jwk/generate :rsa {:size 2048 :kid "rsa"})
        source (jwks/local-source [(jwk/public-jwk key)])
        selector (proc/jws-key-selector :rsa source)
        processor (proc/processor source {:jws-algs #{:rs256}
                                          :jwe-algs #{:dir}
                                          :jwe-encs #{:a256gcm}
                                          :jws-key-selector selector})
        compact (jws/sign key "family payload" {:alg :rs512})]
    (is (= "family payload" (:payload (proc/process processor compact))))))

(deftest single-key-selector-round-trips-and-context-keys-work
  (let [key (jwk/generate :oct {:size 256})
        compact (jws/sign key "single key")
        selector (proc/single-key-selector :hs256 key)
        source (jwks/local-source [])
        processor (proc/processor source {:jws-algs #{:hs256}
                                          :jwe-algs #{:dir}
                                          :jwe-encs #{:a256gcm}
                                          :jws-key-selector selector})
        context (proc/security-context [key])
        context-selector (proc/jws-key-selector :hmac-sha nil)
        context-processor (proc/processor source {:jws-algs #{:hs256}
                                                   :jwe-algs #{:dir}
                                                   :jwe-encs #{:a256gcm}
                                                   :jws-key-selector context-selector})]
    (is (= "single key" (:payload (proc/process processor compact))))
    (is (= "single key" (:payload (proc/process context-processor compact context))))))

(deftest matcher-supports-all-criteria
  (let [key (jwk/generate :oct {:size 256 :kid "match"})
        source (jwks/local-source [key])
        compact (jws/sign key "payload" {:headers {:jku "https://example.test/keys"}})
        object (JWSObject/parse compact)
        encrypted (JWEObject/parse (jwe/encrypt key "payload" {:alg :dir :enc :a256gcm}))
        matches (proc/matcher {:classes #{JWSObject}
                               :algorithms #{:hs256}
                               :jwk-urls #{"https://example.test/keys"}
                               :key-ids #{"match"}})]
    (is (matches object))
    (is (not ((proc/matcher {:classes #{JWEObject}}) object)))
    (is (not ((proc/matcher {:algorithms #{:rs256}}) object)))
    (is ((proc/matcher {:encryption-methods #{:a256gcm}}) encrypted))
    (is (not ((proc/matcher {:encryption-methods #{:a128gcm}}) encrypted)))
    (is (not ((proc/matcher {:jwk-urls #{"https://other.example/keys"}}) object)))
    (is (not ((proc/matcher {:key-ids #{"other"}}) object)))
    (is (= :invalid-option
           (:jose/error (thrown-data #(proc/processor source (assoc (policy source)
                                                                     :unknown true))))))))

(deftest eddsa-keywords-are-valid-algorithms
  (let [key (jwk/generate :okp {:curve :ed25519 :kid "ed" :alg :eddsa :use :sig})
        source (jwks/local-source [(jwk/public-jwk key)])
        processor (proc/processor source {:jws-algs #{:eddsa}
                                          :jws-key-selector (proc/jws-key-selector :signature source)})
        compact (jws/sign key "ed payload")]
    (is (= #{JWSAlgorithm/EdDSA} (:jws-algs processor)))
    (is (= "ed payload" (:payload (jws/verify (jwk/public-jwk key) compact {:alg :eddsa}))))
    (is (= :invalid-option
           (:jose/error (thrown-data #(proc/processor source {:jws-algs #{:unknown}})))))))

(deftest processor-sides-are-independent
  (let [sign-key (jwk/generate :oct {:size 256})
        encrypt-key (jwk/generate :oct {:size 256})
        signed (jws/sign sign-key "signed")
        encrypted (jwe/encrypt encrypt-key "encrypted" {:alg :dir})
        jws-only (proc/processor (jwks/local-source [sign-key]) {:jws-algs #{:hs256}})
        jwe-only (proc/processor (jwks/local-source [encrypt-key]) {:jwe-algs #{:dir}
                                                                     :jwe-encs #{:a256gcm}})]
    (is (= "signed" (:payload (proc/process jws-only signed))))
    (is (= :key-not-found (:jose/error (thrown-data #(proc/process jws-only encrypted)))))
    (is (= "encrypted" (:payload (proc/process jwe-only encrypted))))
    (is (= :key-not-found (:jose/error (thrown-data #(proc/process jwe-only signed)))))
    (is (= :invalid-option
           (:jose/error (thrown-data #(proc/processor (jwks/local-source [sign-key]) {})))))))

(deftest okp-single-key-selector-accepts-java-key
  (let [key-pair (.generateKeyPair (java.security.KeyPairGenerator/getInstance "Ed25519"))]
    (is (instance? com.nimbusds.jose.proc.JWSKeySelector
                 (proc/single-key-selector :eddsa (.getPublic key-pair))))))

(deftest matcher-accepts-keyword-classes
  (let [key (jwk/generate :oct {:size 256})
        object (JWSObject/parse (jws/sign key "payload"))]
    (is ((proc/matcher {:classes #{:jws}}) object))
    (is (not ((proc/matcher {:classes #{:jwe}}) object)))
    (is ((proc/matcher {:classes #{:jose}}) object))))

(deftest proc-and-jwe-share-the-same-algorithm-vocabulary
  (let [jwe-algs (var-get (ns-resolve 'jose.jwe 'alg-names))
        proc-algs (var-get (ns-resolve 'jose.proc 'jwe-algorithm-values))]
    (is (= (set (keys jwe-algs)) (set (keys proc-algs))))))

(deftest unsupported-algorithms-are-not-in-the-vocabulary
  (let [source (jwks/local-source [])]
    (is (= :invalid-option
           (:jose/error (thrown-data #(proc/processor source {:jws-algs #{:ed448}})))))
    (is (= :invalid-option
           (:jose/error (thrown-data #(proc/processor source {:jwe-algs #{:rsa1-5}
                                                              :jwe-encs #{:a256gcm}})))))
    (is (= :invalid-option
           (:jose/error (thrown-data #(proc/processor source {:jwe-algs #{:rsa-oaep}
                                                              :jwe-encs #{:a256gcm}})))))))

(deftest jwe-policy-requires-both-algorithm-and-encryption-allow-lists
  (let [source (jwks/local-source [])]
    (is (= :invalid-option
           (:jose/error (thrown-data #(proc/processor source {:jwe-algs #{:dir}})))))
    (is (= :invalid-option
           (:jose/error (thrown-data #(proc/processor source {:jwe-encs #{:a256gcm}})))))))

(deftest pins-nimbus-1091-eddsa-jwk-source-limitation
  ;; Nimbus 10.9.1 JWSVerificationKeySelector returns no EdDSA key from JWKSource.
  (let [key (.generate (OctetKeyPairGenerator. Curve/Ed25519))
        source (ImmutableJWKSet. (JWKSet. [key]))
        selector (JWSVerificationKeySelector. #{JWSAlgorithm/EdDSA} source)
        header (JWSHeader. JWSAlgorithm/EdDSA)]
    (is (empty? (.selectJWSKeys selector header (SimpleSecurityContext.))))))
