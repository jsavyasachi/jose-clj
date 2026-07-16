(ns jose.jws-test
  (:require [clojure.test :refer [deftest is testing]]
            [jose.jwk :as jwk]
            [jose.jwks :as jwks]
            [jose.jws :as jws])
  (:import (clojure.lang ExceptionInfo)
           (com.nimbusds.jose.jwk Curve OctetSequenceKey$Builder)
           (com.nimbusds.jose.jwk.gen ECKeyGenerator)
           (com.nimbusds.jose.util Base64URL)
           (java.nio.charset StandardCharsets)
           (org.bouncycastle.jce.provider BouncyCastleProvider)))

(def rfc-jws-payload
  (str "{\"iss\":\"joe\",\r\n"
       " \"exp\":1300819380,\r\n"
       " \"http://example.com/is_root\":true}"))

;; Test vector sourced from RFC 7515 appendix A.1.
(def rfc-7515-a1-oct-jwk
  {:kty "oct"
   :k "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"})

(def rfc-7515-a1-compact
  (str "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9."
       "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
       "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))

;; Test vector sourced from RFC 7515 appendix A.2.
(def rfc-7515-a2-rsa-jwk
  {:kty "RSA"
   :n "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"
   :e "AQAB"
   :d "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"
   :p "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"
   :q "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"
   :dp "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0"
   :dq "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU"
   :qi "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"})

(def rfc-7515-a2-compact
  (str "eyJhbGciOiJSUzI1NiJ9."
       "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
       "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7"
       "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4"
       "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K"
       "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv"
       "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB"
       "p0igcN_IoypGlUPQGe77Rw"))

;; Test vector sourced from RFC 7515 appendix A.3.
(def rfc-7515-a3-ec-jwk
  {:kty "EC"
   :crv "P-256"
   :x "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
   :y "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
   :d "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"})

(def rfc-7515-a3-compact
  (str "eyJhbGciOiJFUzI1NiJ9."
       "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
       "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA"
       "pmWQxfKTUJqPP3-Kg6NU1Q"))

;; Test vector sourced from RFC 8037 appendix A.4.
(def rfc-8037-a4-ed25519-jwk
  {:kty "OKP"
   :crv "Ed25519"
   :d "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
   :x "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})

(def rfc-8037-a4-compact
  (str "eyJhbGciOiJFZERTQSJ9."
       "RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc."
       "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"))

(defn thrown-data
  [f]
  (try
    (f)
    nil
    (catch ExceptionInfo e
      (ex-data e))))

(defn secp256k1-key
  []
  (-> (ECKeyGenerator. Curve/SECP256K1)
      (.provider (BouncyCastleProvider.))
      (.keyID "ec-k")
      (.generate)))

(deftest rfc-verification-vectors
  (doseq [[label key compact payload] [["RFC 7515 A.1" rfc-7515-a1-oct-jwk rfc-7515-a1-compact rfc-jws-payload]
                                       ["RFC 7515 A.2" rfc-7515-a2-rsa-jwk rfc-7515-a2-compact rfc-jws-payload]
                                       ["RFC 7515 A.3" rfc-7515-a3-ec-jwk rfc-7515-a3-compact rfc-jws-payload]
                                       ["RFC 8037 A.4" rfc-8037-a4-ed25519-jwk rfc-8037-a4-compact "Example of Ed25519 signing"]]]
    (testing label
      (let [result (jws/verify key compact)]
        (is (= payload (:payload result)))
        (is (= (vec (.getBytes ^String payload StandardCharsets/UTF_8))
               (vec (:payload-bytes result))))))))

(deftest sign-and-verify-round-trips
  (doseq [[kty opts alg] [[:rsa {:size 2048 :kid "rsa-1"} :rs256]
                          [:ec {:curve :p-256 :kid "ec-1"} :es256]
                          [:ec {:curve :p-384 :kid "ec-384"} :es384]
                          [:ec {:curve :p-521 :kid "ec-521"} :es512]
                          [:okp {:curve :ed25519 :kid "okp-1"} :eddsa]
                          [:oct {:size 256 :kid "oct-1"} :hs256]]]
    (testing kty
      (let [key (jwk/generate kty opts)
            compact (jws/sign key "hello" {:headers {:cty "text/plain"}})
            result (jws/verify key compact)]
        (is (= "hello" (:payload result)))
        (is (= alg (get-in result [:header :alg])))
        (is (= (:kid opts) (get-in result [:header :kid])))
        (is (= "text/plain" (get-in result [:header :cty]))))))
  (testing :secp256k1
    (let [key (secp256k1-key)
          compact (jws/sign key "hello")
          result (jws/verify key compact)]
      (is (= "hello" (:payload result)))
      (is (= :es256k (get-in result [:header :alg])))
      (is (= "ec-k" (get-in result [:header :kid]))))))

(deftest explicit-options-and-public-key-verification
  (let [key (jwk/generate :rsa {:kid "from-key"})
        compact (jws/sign (jwk/->map key) "hello" {:alg :rs512
                                                   :kid "explicit"
                                                   :headers {:example "ok"}})]
    (is (= {:alg :rs512 :kid "explicit" :example "ok"}
           (jws/header compact)))
    (is (= "hello" (:payload (jws/verify (jwk/public-jwk key) compact))))))

(deftest verification-policy
  (let [key (jwk/generate :oct {:size 512})
        intended (jws/sign key "hello" {:alg :hs256 :headers {:cty "text/plain"}})
        substituted (jws/sign key "hello" {:alg :hs512})]
    (is (= "hello" (:payload (jws/verify key substituted))))
    (is (= "hello" (:payload (jws/verify key intended {:alg :hs256
                                                         :cty "text/plain"}))))
    (is (= :algorithm-not-allowed
           (:jose/error (thrown-data #(jws/verify key substituted {:algs #{:hs256}})))))
    (is (= :header-mismatch
           (:jose/error (thrown-data #(jws/verify key intended {:cty "application/json"})))))
    (is (= rfc-jws-payload
           (:payload (jws/verify rfc-7515-a1-oct-jwk rfc-7515-a1-compact {:typ "JWT"
                                                                         :alg "HS256"}))))
    (is (= :header-mismatch
           (:jose/error (thrown-data #(jws/verify rfc-7515-a1-oct-jwk
                                                  rfc-7515-a1-compact
                                                  {:typ "JOSE"})))))))

(deftest binary-payloads-return-bytes
  (let [key (jwk/generate :oct {:size 256})
        bytes (byte-array [0 1 2 -1])
        result (jws/verify key (jws/sign key bytes))]
    (is (= [0 1 2 -1] (vec (:payload-bytes result))))
    (is (= "\u0000\u0001\u0002�" (:payload result)))))

(deftest detached-jws-round-trips
  (let [key (jwk/generate :oct {:size 256})
        compact (jws/sign key "hello" {:detached? true})
        segments (clojure.string/split compact #"\." -1)]
    (is (= 3 (count segments)))
    (is (= "" (second segments)))
    (is (= "hello" (:payload (jws/verify-detached key compact "hello"))))
    (is (= :invalid-signature
           (:jose/error (thrown-data #(jws/verify-detached key compact "tampered")))))))

(deftest unencoded-jws-round-trips
  (let [key (jwk/generate :oct {:size 256})
        attached (jws/sign key "hello" {:b64? false})
        detached (jws/sign key "$.02" {:detached? true :b64? false})]
    (is (clojure.string/includes? attached ".hello."))
    (is (= "hello" (:payload (jws/verify key attached))))
    (is (= "$.02" (:payload (jws/verify-detached key detached "$.02"))))
    (is (= false (get-in (jws/header attached) [:b64])))
    (is (= ["b64"] (get-in (jws/header attached) [:crit])))
    (is (= "hello" (:payload (jws/verify key attached {:crit #{"b64"}}))))
    (is (= :unsupported-critical-header
           (:jose/error (thrown-data #(jws/verify key attached {:crit #{}})))))))

(deftest verify-with-jwks-selects-key
  (let [key-a (jwk/generate :rsa {:kid "a" :use :sig :alg :rs256})
        key-b (jwk/generate :rsa {:kid "b" :use :sig :alg :rs256})
        key-c (jwk/generate :rsa {:kid "c" :use :sig :alg :rs256})
        source (jwks/local-source [(jwk/public-jwk key-a) (jwk/public-jwk key-b)])
        compact (jws/sign key-a "hello")]
    (is (= "hello" (:payload (jws/verify-with-jwks source compact))))
    (is (= "hello" (:payload (jws/verify-with-jwks source compact {:alg :rs256}))))
    (is (= "a" (get-in (jws/verify-with-jwks source compact) [:header :kid])))
    (is (= :key-not-found
           (:jose/error (thrown-data #(jws/verify-with-jwks source
                                                            (jws/sign key-c "hello"))))))
    (is (= :ambiguous-key
           (:jose/error (thrown-data #(jws/verify-with-jwks source
                                                            (jws/sign key-a "hello" {:kid nil}))))))))

(deftest alg-confusion-attack-is-rejected
  ;; A JWKS serves only an RSA public key, with no "alg" param (as many real
  ;; endpoints do). An attacker forges an HS256 token using the RSA public key
  ;; material as the HMAC secret and sets the kid to match. Because the verifier
  ;; is chosen from the key type (RSA -> RSASSAVerifier), never from the token's
  ;; header alg, the forgery must not be accepted.
  (let [rsa (jwk/generate :rsa {:kid "a" :use :sig})
        pub (jwk/public-jwk rsa)
        source (jwks/local-source [pub])
        secret (.decode (Base64URL. (name (:n (jwk/->map pub)))))
        forged-key (-> (OctetSequenceKey$Builder. (Base64URL/encode ^bytes secret))
                       (.keyID "a")
                       (.build))
        forged (jws/sign forged-key "pwned" {:alg :hs256})]
    (is (contains? #{:key-not-found :invalid-signature}
                   (:jose/error (thrown-data #(jws/verify-with-jwks source forged)))))))

(deftest unsecured-alg-none-token-is-rejected
  ;; The classic "alg":"none" forgery: a header of {"alg":"none"} with an empty
  ;; signature. It must never verify against a real key.
  (let [b64 (fn [^String s]
              (-> (java.util.Base64/getUrlEncoder)
                  (.withoutPadding)
                  (.encodeToString (.getBytes s StandardCharsets/UTF_8))))
        forged (str (b64 "{\"alg\":\"none\"}") "." (b64 "{\"sub\":\"attacker\"}") ".")
        key (jwk/generate :rsa {:kid "a"})]
    (is (contains? #{:parse-failure :invalid-signature}
                   (:jose/error (thrown-data #(jws/verify key forged)))))))

(deftest failures-are-ex-info
  (let [key (jwk/generate :oct {:size 256})
        compact (jws/sign key "hello")
        tampered (str compact "x")]
    (is (= :invalid-signature
           (:jose/error (thrown-data #(jws/verify key tampered)))))
    (is (= :parse-failure
           (:jose/error (thrown-data #(jws/verify key "not-a-jws")))))
    (is (= :invalid-option
           (:jose/error (thrown-data #(jws/sign key "hello" {:unknown true})))))
    (is (= :unknown
           (:option (thrown-data #(jws/sign key "hello" {:unknown true})))))))
