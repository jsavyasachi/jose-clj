(ns jose.jwks-test
  (:require [clojure.test :refer [deftest is testing]]
            [jose.jwk :as jwk]
            [jose.jwks :as jwks])
  (:import (clojure.lang ExceptionInfo)))

(defn thrown-data
  [f]
  (try
    (f)
    nil
    (catch ExceptionInfo e
      (ex-data e))))

(deftest local-sources-select-keys
  (let [rsa-a (jwk/generate :rsa {:kid "a" :use :sig :alg :rs256})
        rsa-b (jwk/generate :rsa {:kid "b" :use :enc})
        oct-c (jwk/generate :oct {:kid "c" :use :sig})
        source (jwks/local-source [rsa-a rsa-b oct-c])]
    (testing "no matcher fields returns all keys"
      (is (= ["a" "b" "c"] (mapv jwk/key-id (jwks/get-keys source {})))))
    (testing "filters by kid"
      (is (= ["a"] (mapv jwk/key-id (jwks/get-keys source {:kid "a"})))))
    (testing "filters by key type"
      (is (= ["a" "b"] (mapv jwk/key-id (jwks/get-keys source {:kty :rsa})))))
    (testing "filters by key use"
      (is (= ["a" "c"] (mapv jwk/key-id (jwks/get-keys source {:use :sig})))))
    (testing "filters by algorithm"
      (is (= ["a"] (mapv jwk/key-id (jwks/get-keys source {:alg :rs256})))))
    (testing "empty vector on no match"
      (is (= [] (jwks/get-keys source {:kid "missing"}))))
    (testing "find-key returns one matching key"
      (is (= "a" (jwk/key-id (jwks/find-key source "a"))))
      (is (nil? (jwks/find-key source "missing"))))))

(deftest remote-source-rejects-invalid-url
  (is (= :invalid-url
         (:jose/error (thrown-data #(jwks/remote-source "not a url"))))))

(deftest ^:integration google-jwks-has-rsa-keys
  (let [source (jwks/remote-source "https://www.googleapis.com/oauth2/v3/certs")]
    (is (pos? (count (jwks/get-keys source {:kty :rsa}))))))
