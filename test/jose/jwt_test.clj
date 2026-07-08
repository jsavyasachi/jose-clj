(ns jose.jwt-test
  (:require [clojure.test :refer [deftest is testing]]
            [jose.jwk :as jwk]
            [jose.jwt :as jwt])
  (:import (clojure.lang ExceptionInfo)
           (java.time Instant)))

(defn thrown
  [f]
  (try
    (f)
    nil
    (catch ExceptionInfo e
      e)))

(defn thrown-data
  [f]
  (some-> (thrown f) ex-data))

(deftest sign-and-verify-claims
  (let [key (jwk/generate :rsa {:kid "jwt-rsa"})
        exp (Instant/parse "2035-01-01T00:00:00Z")
        iat (Instant/parse "2034-12-31T23:00:00Z")
        compact (jwt/sign key {:iss "issuer"
                               "sub" "subject"
                               :aud ["api" "mobile"]
                               :exp exp
                               :iat iat
                               "role" "admin"})
        claims (jwt/verify (jwk/public-jwk key) compact {:aud "api"
                                                         :iss "issuer"
                                                         :required [:sub "role"]})]
    (is (= "issuer" (:iss claims)))
    (is (= "subject" (:sub claims)))
    (is (= ["api" "mobile"] (:aud claims)))
    (is (= exp (:exp claims)))
    (is (= iat (:iat claims)))
    (is (= "admin" (get claims "role")))))

(deftest claims-are-available-without-verification
  (let [key (jwk/generate :oct {:size 256})
        compact (jwt/sign key {:sub "subject"
                               :exp 2051222400
                               "custom" true})]
    (is (= {:sub "subject"
            :exp (Instant/parse "2035-01-01T00:00:00Z")
            "custom" true}
           (jwt/claims compact)))))

(deftest auto-claims
  (let [key (jwk/generate :oct {:size 256})
        before (Instant/now)
        compact (jwt/sign key {:sub "subject"} {:now-iat? true
                                                :expires-in 3600})
        after (Instant/now)
        claims (jwt/verify key compact)]
    (is (not (.isBefore ^Instant (:iat claims) (.minusSeconds before 1))))
    (is (not (.isAfter ^Instant (:iat claims) after)))
    (is (= 3600 (- (.getEpochSecond ^Instant (:exp claims))
                   (.getEpochSecond ^Instant (:iat claims)))))))

(deftest validation-failures
  (let [key (jwk/generate :oct {:size 256})
        now (Instant/now)
        expired (jwt/sign key {:sub "subject" :exp (.minusSeconds now 10)})
        future (jwt/sign key {:sub "subject" :nbf (.plusSeconds now 60)})
        audience (jwt/sign key {:sub "subject" :aud ["api"] :exp (.plusSeconds now 60)})
        issuer (jwt/sign key {:sub "subject" :iss "issuer" :exp (.plusSeconds now 60)})
        no-sub (jwt/sign key {:iss "issuer" :exp (.plusSeconds now 60)})
        skewed (jwt/sign key {:sub "subject" :exp (.minusSeconds now 30)})]
    (is (= :expired (:jose/error (thrown-data #(jwt/verify key expired)))))
    (is (= :not-yet-valid (:jose/error (thrown-data #(jwt/verify key future)))))
    (is (= :claim-mismatch (:jose/error (thrown-data #(jwt/verify key audience {:aud "web"})))))
    (is (= :aud (:claim (thrown-data #(jwt/verify key audience {:aud "web"})))))
    (is (= :claim-mismatch (:jose/error (thrown-data #(jwt/verify key issuer {:iss "other"})))))
    (is (= :iss (:claim (thrown-data #(jwt/verify key issuer {:iss "other"})))))
    (is (= :missing-claim (:jose/error (thrown-data #(jwt/verify key no-sub {:required [:sub]})))))
    (is (= :sub (:claim (thrown-data #(jwt/verify key no-sub {:required [:sub]})))))
    (is (= "subject" (:sub (jwt/verify key skewed {:clock-skew 60}))))))

(deftest invalid-signatures-and-input
  (let [key (jwk/generate :oct {:size 256})
        other (jwk/generate :oct {:size 256})
        compact (jwt/sign key {:sub "subject" :exp 2051222400})]
    (is (= :invalid-signature
           (:jose/error (thrown-data #(jwt/verify other compact)))))
    (is (= :parse-failure
           (:jose/error (thrown-data #(jwt/verify key "not-a-jwt")))))))

(deftest invalid-options-are-rejected
  (let [key (jwk/generate :oct {:size 256})]
    (testing "sign"
      (is (= :invalid-option
             (:jose/error (thrown-data #(jwt/sign key {:sub "subject"} {:unknown true})))))
      (is (= :unknown
             (:option (thrown-data #(jwt/sign key {:sub "subject"} {:unknown true}))))))
    (testing "verify"
      (is (= :invalid-option
             (:jose/error (thrown-data #(jwt/verify key (jwt/sign key {:sub "subject"}) {:unknown true})))))
      (is (= :unknown
             (:option (thrown-data #(jwt/verify key (jwt/sign key {:sub "subject"}) {:unknown true}))))))))
