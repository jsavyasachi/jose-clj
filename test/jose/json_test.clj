(ns jose.json-test
  (:require [clojure.test :refer [deftest is testing]]
            [jose.jwe :as jwe]
            [jose.jwk :as jwk]
            [jose.jws :as jws])
  (:import (com.nimbusds.jose.util JSONObjectUtils)))

(deftest flattened-jws-json-round-trip
  (let [key (jwk/generate :rsa {:kid "sig-1"})
        json (jws/sign-json key "flattened jws"
                            {:serialization :flattened
                             :alg :rs256
                             :protected-headers {:typ "JOSE"}
                             :unprotected-headers {:kid "sig-1" :source "local"}})
        parsed (JSONObjectUtils/parse json)
        result (jws/verify-json key json {:algs #{:rs256} :typ "JOSE"})]
    (is (contains? parsed "signature"))
    (is (not (contains? parsed "signatures")))
    (is (= "flattened jws" (:payload result)))
    (is (= {:kid "sig-1" :source "local"}
           (get-in result [:signatures 0 :unprotected-header])))))

(deftest general-jws-json-round-trip
  (let [rsa (jwk/generate :rsa {:kid "rsa"})
        ec (jwk/generate :ec {:curve :p-256 :kid "ec"})
        signers [{:key rsa
                  :alg :rs256
                  :protected-headers {:typ "JOSE"}
                  :unprotected-headers {:kid "rsa"}}
                 {:key ec
                  :alg :es256
                  :protected-headers {:typ "JOSE"}
                  :unprotected-headers {:kid "ec"}}]
        json (jws/sign-json signers "general jws" {:serialization :general})
        parsed (JSONObjectUtils/parse json)
        result (jws/verify-json [(jwk/public-jwk rsa) (jwk/public-jwk ec)]
                                json
                                {:algs #{:rs256 :es256} :typ "JOSE"})]
    (is (= 2 (count (get parsed "signatures"))))
    (is (= "general jws" (:payload result)))
    (is (= #{"rsa" "ec"}
           (set (map #(get-in % [:unprotected-header :kid]) (:signatures result)))))))

(deftest flattened-jwe-json-round-trip
  (let [key (jwk/generate :rsa {:kid "enc-1"})
        json (jwe/encrypt-json key "flattened jwe"
                              {:serialization :flattened
                               :alg :rsa-oaep-256
                               :enc :a256gcm
                               :protected-headers {:cty "text/plain"}
                               :unprotected-headers {:source "local"}})
        parsed (JSONObjectUtils/parse json)
        result (jwe/decrypt-json key json)]
    (is (contains? parsed "encrypted_key"))
    (is (not (contains? parsed "recipients")))
    (is (= "flattened jwe" (:payload result)))
    (is (= "text/plain" (get-in result [:protected-header :cty])))
    (is (= {:source "local"} (:unprotected-header result)))))

(deftest general-jwe-json-round-trip
  (let [a (jwk/generate :rsa {:kid "a"})
        b (jwk/generate :rsa {:kid "b"})
        json (jwe/encrypt-json [(jwk/public-jwk a) (jwk/public-jwk b)]
                              "general jwe"
                              {:serialization :general
                               :alg :rsa-oaep-256
                               :enc :a256gcm
                               :protected-headers {:cty "text/plain"}
                               :unprotected-headers {:issuer "local"}})
        parsed (JSONObjectUtils/parse json)]
    (is (= 2 (count (get parsed "recipients"))))
    (doseq [key [a b]]
      (let [result (jwe/decrypt-json key json)]
        (is (= "general jwe" (:payload result)))
        (is (= "text/plain" (get-in result [:protected-header :cty])))
        (is (= {:issuer "local"} (:unprotected-header result)))))))
