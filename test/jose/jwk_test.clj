(ns jose.jwk-test
  (:require [clojure.test :refer [deftest is testing]]
            [jose.jwk :as jwk])
  (:import (clojure.lang ExceptionInfo)
           (com.nimbusds.jose.jwk JWK JWKSet)))

;; Test vector sourced from RFC 7638 section 3.1.
(def rfc-7638-rsa-jwk
  {:kty "RSA"
   :n "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
   :e "AQAB"
   :alg "RS256"
   :kid "2011-04-29"})

;; Test vector sourced from RFC 8037 appendix A.3.
(def rfc-8037-ed25519-jwk
  {:kty "OKP"
   :crv "Ed25519"
   :x "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})

(deftest rfc-thumbprints
  (is (= "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
         (jwk/thumbprint (jwk/parse rfc-7638-rsa-jwk))))
  (is (= "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
         (jwk/thumbprint (jwk/parse rfc-8037-ed25519-jwk)))))

(deftest generate-round-trips-through-maps
  (doseq [[kty opts expected-type] [[:rsa {:size 2048 :use :sig :alg :rs256} :rsa]
                                    [:ec {:curve :p-256 :use :sig :alg :es256} :ec]
                                    [:okp {:curve :ed25519 :use :sig :alg :eddsa} :okp]
                                    [:oct {:size 256 :use :enc :alg :a256kw} :oct]]]
    (testing kty
      (let [generated (jwk/generate kty (assoc opts :kid (str (name kty) "-kid")))
            parsed (jwk/parse (jwk/->map generated))]
        (is (instance? JWK generated))
        (is (= expected-type (jwk/key-type parsed)))
        (is (= (str (name kty) "-kid") (jwk/key-id parsed)))
        (is (jwk/private? parsed))
        (is (= (jwk/thumbprint generated) (jwk/thumbprint parsed)))))))

(deftest generate-adds-kid-from-thumbprint-by-default
  (let [generated (jwk/generate :rsa {})]
    (is (= (jwk/thumbprint generated) (jwk/key-id generated)))))

(deftest conversion-and-public-views
  (let [rsa (jwk/generate :rsa {:kid "rsa-1"})
        rsa-public (jwk/public-jwk rsa)
        oct (jwk/generate :oct {:kid "oct-1"})
        rsa-map (jwk/->map rsa)]
    (is (contains? rsa-map :d))
    (is (= rsa-map (jwk/->map (jwk/parse (jwk/->json rsa)))))
    (is (not (jwk/private? rsa-public)))
    (is (nil? (jwk/public-jwk oct)))
    (is (not (contains? (jwk/->map rsa-public) :d)))
    (is (not (contains? (jwk/->map (jwk/parse (jwk/->json rsa {:private? false}))) :d)))))

(deftest parse-failure-is-ex-info
  (let [thrown (try
                 (jwk/parse "{not-json")
                 nil
                 (catch ExceptionInfo e
                   e))]
    (is (= :parse-failure (:jose/error (ex-data thrown))))
    (is (some? (ex-cause thrown)))))

(deftest invalid-options-are-rejected
  (let [thrown (try
                 (jwk/generate :rsa {:unknown true})
                 nil
                 (catch ExceptionInfo e
                   e))]
    (is (= :invalid-option (:jose/error (ex-data thrown))))
    (is (= :unknown (:option (ex-data thrown))))))

(deftest jwk-sets
  (let [rsa (jwk/generate :rsa {:kid "rsa-1"})
        oct (jwk/generate :oct {:kid "oct-1"})
        jwks (jwk/jwk-set [rsa oct])
        public-json (jwk/set->json jwks)
        parsed-public (jwk/parse-set public-json)
        private-json (jwk/set->json jwks {:private? true})
        parsed-private (jwk/parse-set private-json)]
    (is (instance? JWKSet jwks))
    (is (= "rsa-1" (jwk/key-id (jwk/find-key jwks "rsa-1"))))
    (is (nil? (jwk/find-key jwks "missing")))
    (is (= [:rsa] (mapv jwk/key-type (.getKeys parsed-public))))
    (is (not (contains? (first (jwk/set->maps parsed-public)) :d)))
    (is (= #{:rsa :oct} (set (map jwk/key-type (.getKeys parsed-private)))))
    (is (some #(contains? % :d) (jwk/set->maps parsed-private)))))
