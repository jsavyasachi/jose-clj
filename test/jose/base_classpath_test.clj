(ns jose.base-classpath-test
  (:require [clojure.test :refer [deftest is]]
            [jose.jwk :as jwk]
            [jose.jws :as jws])
  (:import (clojure.lang ExceptionInfo)))

(def public-namespaces
  '[jose.jwe
    jose.jwk
    jose.jwks
    jose.jws
    jose.jwt
    jose.keyring
    jose.mint
    jose.pem
    jose.proc
    jose.ring])

(deftest public-namespaces-load-with-base-deps
  (doseq [namespace public-namespaces]
    (require namespace)
    (is true (str "Loaded " namespace))))

(deftest missing-provider-is-a-typed-error
  (let [key (jwk/generate :oct {:size 256})
        compact (jws/sign key "hello")
        error (try
                (jws/verify key compact {:alg :hs256 :provider :bouncy-castle})
                nil
                (catch ExceptionInfo e
                  (ex-data e)))]
    (is (= :missing-optional-dep (:jose/error error)))
    (is (= "org.bouncycastle/bcprov-jdk18on" (:dep error)))))

(defn -main
  [& _]
  (let [result (clojure.test/run-tests 'jose.base-classpath-test)]
    (when (pos? (+ (:fail result) (:error result)))
      (System/exit 1))))
