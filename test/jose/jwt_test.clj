(ns jose.jwt-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [jose.jwe :as jwe]
            [jose.jwk :as jwk]
            [jose.jwks :as jwks]
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

(deftest verify-with-jwks-selects-key-and-validates-claims
  (let [key-a (jwk/generate :rsa {:kid "a" :use :sig :alg :rs256})
        key-b (jwk/generate :rsa {:kid "b" :use :sig :alg :rs256})
        key-c (jwk/generate :rsa {:kid "c" :use :sig :alg :rs256})
        source (jwks/local-source [(jwk/public-jwk key-a) (jwk/public-jwk key-b)])
        compact (jwt/sign key-a {:sub "subject" :aud ["api"] :exp 2051222400})]
    (is (= "subject" (:sub (jwt/verify-with-jwks source compact {:aud "api"}))))
    (is (= :claim-mismatch
           (:jose/error (thrown-data #(jwt/verify-with-jwks source compact {:aud "web"})))))
    (is (= :key-not-found
           (:jose/error (thrown-data #(jwt/verify-with-jwks source
                                                            (jwt/sign key-c {:sub "subject"
                                                                             :exp 2051222400}))))))
    (is (= :ambiguous-key
           (:jose/error (thrown-data #(jwt/verify-with-jwks source
                                                            (jwt/sign key-a
                                                                      {:sub "subject"
                                                                       :exp 2051222400}
                                                                      {:kid nil}))))))))

(deftest invalid-signatures-and-input
  (let [key (jwk/generate :oct {:size 256})
        other (jwk/generate :oct {:size 256})
        compact (jwt/sign key {:sub "subject" :exp 2051222400})]
    (is (= :invalid-signature
           (:jose/error (thrown-data #(jwt/verify other compact)))))
    (is (= :parse-failure
           (:jose/error (thrown-data #(jwt/verify key "not-a-jwt")))))))

(deftest verification-policy-rejects-algorithm-substitution
  (let [key (jwk/generate :oct {:size 512})
        intended (jwt/sign key {:sub "subject" :exp 2051222400} {:alg :hs256})
        substituted (jwt/sign key {:sub "subject" :exp 2051222400} {:alg :hs512})]
    (is (= "subject" (:sub (jwt/verify key substituted))))
    (is (= "subject" (:sub (jwt/verify key intended {:algs #{:hs256}}))))
    (is (= "subject" (:sub (jwt/verify key intended {:alg "HS256"}))))
    (is (= :algorithm-not-allowed
           (:jose/error (thrown-data #(jwt/verify key substituted {:algs #{:hs256}})))))))

(deftest verification-policy-validates-headers-and-token-age
  (let [key (jwk/generate :oct {:size 256})
        now (Instant/now)
        compact (jwt/sign key
                          {:sub "subject" :iat (.minusSeconds now 120) :exp 2051222400}
                          {:headers {:typ "JWT" :cty "application/example"}})
        no-iat (jwt/sign key {:sub "subject" :exp 2051222400})]
    (is (= "subject" (:sub (jwt/verify key compact {:typ "JWT"
                                                     :cty "application/example"
                                                     :max-age 180}))))
    (is (= :header-mismatch
           (:jose/error (thrown-data #(jwt/verify key compact {:typ "JOSE"})))))
    (is (= :header-mismatch
           (:jose/error (thrown-data #(jwt/verify key compact {:cty "application/json"})))))
    (is (= :too-old
           (:jose/error (thrown-data #(jwt/verify key compact {:max-age 60})))))
    (is (= :missing-claim
           (:jose/error (thrown-data #(jwt/verify key no-iat {:max-age 60})))))))

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

(deftest encrypt-and-decrypt-claims
  (let [key (jwk/generate :rsa {:kid "jwt-jwe"})
        exp (Instant/parse "2035-01-01T00:00:00Z")
        compact (jwt/encrypt key {:iss "issuer"
                                  :aud ["api"]
                                  :exp exp
                                  "role" "admin"}
                             {:headers {:cty "JWT"}})
        claims (jwt/decrypt key compact {:aud "api"
                                         :iss "issuer"
                                         :required ["role"]})]
    (is (= {:alg :rsa-oaep-256 :enc :a256gcm :kid "jwt-jwe" :cty "JWT"}
           (select-keys (jwe/header compact) [:alg :enc :kid :cty])))
    (is (= "issuer" (:iss claims)))
    (is (= ["api"] (:aud claims)))
    (is (= exp (:exp claims)))
    (is (= "admin" (get claims "role")))))

(deftest nested-jwt-round-trip
  (let [sign-key (jwk/generate :oct {:size 256})
        encrypt-key (jwk/generate :rsa {:kid "nested-rsa"})
        claims {:sub "subject" :aud ["api"] :exp 2051222400}
        compact (jwt/sign-then-encrypt sign-key encrypt-key claims
                                       {:sign-opts {:headers {:typ "JWT"}}
                                        :encrypt-opts {:enc :a128gcm}})
        inner (:payload (jwe/decrypt encrypt-key compact))]
    (is (= "JWT" (:cty (jwe/header compact))))
    (is (= 3 (count (str/split inner #"\."))))
    (is (= "subject"
           (:sub (jwt/decrypt-then-verify encrypt-key sign-key compact {:aud "api"}))))
    (is (= :invalid-signature
           (:jose/error (thrown-data #(jwt/decrypt-then-verify encrypt-key
                                                               (jwk/generate :oct {:size 256})
                                                               compact
                                                               {:aud "api"})))))))

(deftest nested-jwt-rejects-non-jwt-payload
  (let [key (jwk/generate :oct {:size 256})
        compact (jwe/encrypt key "not-a-jwt" {:alg :dir :headers {:cty "JWT"}})]
    (is (= :not-a-nested-jwt
           (:jose/error (thrown-data #(jwt/decrypt-then-verify key key compact)))))))

(deftest nested-jwt-rejects-tampered-inner-signature
  (let [sign-key (jwk/generate :oct {:size 256})
        encrypt-key (jwk/generate :oct {:size 256})
        signed (jwt/sign sign-key {:sub "subject" :exp 2051222400})
        tampered (str signed "x")
        compact (jwe/encrypt encrypt-key tampered {:alg :dir :headers {:cty "JWT"}})]
    (is (= :invalid-signature
           (:jose/error (thrown-data #(jwt/decrypt-then-verify encrypt-key
                                                               sign-key
                                                               compact)))))))
