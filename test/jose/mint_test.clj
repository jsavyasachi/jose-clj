(ns jose.mint-test
  (:require [clojure.test :refer [deftest is testing]]
            [jose.jwk :as jwk]
            [jose.jws :as jws]
            [jose.jwks :as jwks]
            [jose.mint :as mint])
  (:import (clojure.lang ExceptionInfo)
           (com.nimbusds.jose JWSAlgorithm JWSSigner JOSEException KeySourceException)
           (com.nimbusds.jose.crypto.factories DefaultJWSSignerFactory)
           (com.nimbusds.jose.jwk JWK JWKSet)
           (com.nimbusds.jose.jwk.source JWKSource)
           (com.nimbusds.jose.jwk JWKSelector)
           (com.nimbusds.jose.proc SecurityContext)
           (com.nimbusds.jose.produce JWSSignerFactory)
           (com.nimbusds.jose.jca JCAContext)
           (java.util Set)))

(defn thrown-data
  [f]
  (try
    (f)
    nil
    (catch ExceptionInfo e
      (ex-data e))))

(defn counting-factory
  [calls]
  (let [delegate (DefaultJWSSignerFactory.)]
    (reify JWSSignerFactory
      (^JWSSigner createJWSSigner [_ ^JWK key]
        (swap! calls inc)
        (.createJWSSigner delegate key))
      (^JWSSigner createJWSSigner [_ ^JWK key ^JWSAlgorithm algorithm]
        (swap! calls inc)
        (.createJWSSigner delegate key algorithm))
      (^JCAContext getJCAContext [_]
        (.getJCAContext delegate))
      (^Set supportedJWSAlgorithms [_]
        (.supportedJWSAlgorithms delegate)))))

(deftest mints-by-kid-and-verifies
  (let [rsa-a (jwk/generate :rsa {:kid "a" :use :sig :alg :rs256})
        rsa-b (jwk/generate :rsa {:kid "b" :use :sig :alg :rs256})
        source (jwks/local-source [rsa-a rsa-b])
        minter (mint/minter source)
        compact (mint/mint minter "hello" {:alg :rs256 :kid "b" :typ "JWT"
                                             :cty "claims" :headers {:role "admin"}})]
    (is (= source (mint/source minter)))
    (is (= "hello" (:payload (jws/verify rsa-b compact {:alg :rs256}))))
    (is (= "hello" (:payload (jws/verify-with-jwks source compact {:alg :rs256}))))
    (is (= {:alg :rs256 :kid "b" :typ "JWT" :cty "claims" :role "admin"}
           (select-keys (jws/header compact) [:alg :kid :typ :cty :role])))))

(deftest selects-by-algorithm-across-key-types
  (let [rsa (jwk/generate :rsa {:kid "rsa" :use :sig :alg :rs256})
        oct (jwk/generate :oct {:kid "oct" :use :sig :alg :hs256})
        source (jwks/local-source [rsa oct])
        compact (mint/mint (mint/minter source) "hello" {:alg :hs256})]
    (is (= "oct" (:kid (jws/header compact))))
    (is (= "hello" (:payload (jws/verify oct compact {:alg :hs256}))))
    (is (= "hello" (:payload (jws/verify-with-jwks source compact {:alg :hs256}))))))

(deftest accepts-jwkset-and-vector-sources
  (let [key (jwk/generate :rsa {:kid "one" :use :sig :alg :rs256})
        set (jwk/jwk-set [key])]
    (is (instance? JWKSource (mint/jwk-source (mint/minter set))))
    (is (instance? JWKSource (mint/jwk-source (mint/minter (jwk/set->maps set)))))))

(deftest reports-no-matching-key
  (let [source (jwks/local-source [(jwk/generate :rsa {:kid "known" :alg :rs256})])
        exception (try
                    (mint/mint (mint/minter source) "hello"
                               {:alg :rs256 :kid "missing"})
                    nil
                    (catch ExceptionInfo e e))]
    (is (= :key-not-found (-> exception ex-data :jose/error)))
    ;; DefaultJWSMinter is the source of this message; pin it against Nimbus bumps.
    (is (= "No JWKs found for signing"
           (.getMessage ^JOSEException (.getCause exception))))))

(deftest reports-key-source-failure
  (let [source (reify JWKSource
                 (^java.util.List get [_ ^JWKSelector _ ^SecurityContext _]
                   (throw (KeySourceException. "source unavailable"))))
        error (thrown-data #(mint/mint (mint/minter source) "hello" {:alg :rs256}))]
    (is (= :key-source-failure (:jose/error error)))))

(deftest rejects-unknown-options
  (is (= :invalid-option
         (:jose/error (thrown-data #(mint/mint (mint/minter []) "hello"
                                               {:alg :rs256 :nope true}))))))

(deftest uses-custom-signer-factory
  (let [calls (atom 0)
        factory (counting-factory calls)
        key (jwk/generate :rsa {:kid "custom" :alg :rs256})
        minter (mint/minter [key] {:signer-factory factory})
        compact (mint/mint minter "hello" {:alg :rs256})]
    (is (= factory (mint/signer-factory minter)))
    (is (= 1 @calls))
    (is (= "hello" (:payload (jws/verify key compact {:alg :rs256}))))))
