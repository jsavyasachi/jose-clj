(ns jose.jwe-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [jose.jwe :as jwe]
            [jose.jwk :as jwk])
  (:import (clojure.lang ExceptionInfo)
           (java.nio.charset StandardCharsets)))

(def rfc-7516-rsa-jwk
  {:kty "RSA"
   :n (str "oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW"
           "cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S"
           "psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a"
           "sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS"
           "tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj"
           "YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw")
   :e "AQAB"
   :d (str "kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N"
           "WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9"
           "3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk"
           "qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl"
           "t3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd"
           "VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ")
   :p (str "1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-"
           "SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lf"
           "fNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0")
   :q (str "wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBm"
           "UDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aX"
           "IWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc")
   :dp (str "ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KL"
            "hMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827"
            "rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE")
   :dq (str "Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCj"
            "ywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDB"
            "UfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis")
   :qi (str "VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7"
            "AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3"
            "eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY")})

(def rfc-7516-a1-compact
  (str "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ."
       "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe"
       "ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb"
       "Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV"
       "mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8"
       "1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi"
       "6UklfCpIMfIjf7iGdXKHzg."
       "48V1_ALb6US04U3b."
       "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji"
       "SdiwkIr3ajwQzaBtQD_A."
       "XFBoMYUZodetZdvTiFvSkQ"))

(def rfc-7516-a3-oct-jwk
  {:kty "oct"
   :k "GawgguFyGrWKav7AX4VKUg"})

(def rfc-7516-a3-compact
  (str "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0."
       "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ."
       "AxY8DCtDaGlsbGljb3RoZQ."
       "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY."
       "U0m_YmjN04DJvceFICbCVQ"))

(def rfc-7520-5-5-ec-jwk
  {:kty "EC"
   :kid "meriadoc.brandybuck@buckland.example"
   :use "enc"
   :crv "P-256"
   :x "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0"
   :y "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw"
   :d "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"})

(def rfc-7520-5-5-compact
  (str "eyJhbGciOiJFQ0RILUVTIiwia2lkIjoibWVyaWFkb2MuYnJhbmR5YnVja0BidW"
       "NrbGFuZC5leGFtcGxlIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYi"
       "LCJ4IjoibVBVS1RfYkFXR0hJaGcwVHBqanFWc1AxclhXUXVfdndWT0hIdE5rZF"
       "lvQSIsInkiOiI4QlFBc0ltR2VBUzQ2ZnlXdzVNaFlmR1RUMElqQnBGdzJTUzM0"
       "RHY0SXJzIn0sImVuYyI6IkExMjhDQkMtSFMyNTYifQ.."
       "yc9N8v5sYyv3iGQT926IUg."
       "BoDlwPnTypYq-ivjmQvAYJLb5Q6l-F3LIgQomlz87yW4OPKbWE1zSTEFjDfhU9"
       "IPIOSA9Bml4m7iDFwA-1ZXvHteLDtw4R1XRGMEsDIqAYtskTTmzmzNa-_q4F_e"
       "vAPUmwlO-ZG45Mnq4uhM1fm_D9rBtWolqZSF3xGNNkpOMQKF1Cl8i8wjzRli7-"
       "IXgyirlKQsbhhqRzkv8IcY6aHl24j03C-AR2le1r7URUhArM79BY8soZU0lzwI"
       "-sD5PZ3l4NDCCei9XkoIAfsXJWmySPoeRb2Ni5UZL4mYpvKDiwmyzGd65KqVw7"
       "MsFfI_K767G9C9Azp73gKZD0DyUn1mn0WW5LmyX_yJ-3AROq8p1WZBfG-ZyJ61"
       "95_JGG2m9Csg."
       "WCCkNa-x4BeB9hIDIfFuhg"))

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

(deftest rfc-decryption-vectors
  (testing "RFC 7516 appendix A.1: RSAES-OAEP + A256GCM"
    (is (= "The true sign of intelligence is not knowledge but imagination."
           (:payload (jwe/decrypt rfc-7516-rsa-jwk rfc-7516-a1-compact)))))
  (testing "RFC 7516 appendix A.3: A128KW + A128CBC-HS256"
    (is (= "Live long and prosper."
           (:payload (jwe/decrypt rfc-7516-a3-oct-jwk rfc-7516-a3-compact)))))
  (testing "RFC 7520 section 5.5: ECDH-ES direct"
    (let [result (jwe/decrypt rfc-7520-5-5-ec-jwk rfc-7520-5-5-compact)]
      (is (str/starts-with? (:payload result) "You can trust us to stick with you"))
      (is (map? (get-in (jwe/header rfc-7520-5-5-compact) [:epk]))))))

(deftest encrypt-and-decrypt-round-trips
  (let [payload "hello jwe"
        rsa (jwk/generate :rsa {:kid "rsa-1"})
        ec (jwk/generate :ec {:curve :p-256 :kid "ec-1"})
        x25519 (jwk/generate :okp {:curve :x25519 :kid "x25519-1"})
        oct-128 (jwk/generate :oct {:size 128 :kid "oct-128"})
        oct-256 (jwk/generate :oct {:size 256 :kid "oct-256"})
        cases (concat
               (for [enc [:a128cbc-hs256 :a192cbc-hs384 :a256cbc-hs512
                          :a128gcm :a192gcm :a256gcm]]
                 ["RSA-OAEP-256" rsa {:alg :rsa-oaep-256 :enc enc}])
               [["ECDH-ES" ec {:alg :ecdh-es :enc :a256gcm}]
                ["ECDH-ES+A256KW" ec {:alg :ecdh-es+a256kw :enc :a256gcm}]
                ["X25519 ECDH-ES" x25519 {:alg :ecdh-es :enc :a256gcm}]
                ["A128KW" oct-128 {:alg :a128kw :enc :a256gcm}]
                ["A256GCMKW" oct-256 {:alg :a256gcmkw :enc :a256gcm}]
                ["dir" oct-256 {:alg :dir :enc :a256gcm}]])]
    (doseq [[label key opts] cases]
      (testing label
        (let [compact (jwe/encrypt key payload (assoc opts :headers {:cty "text/plain"}))
              result (jwe/decrypt key compact)]
          (is (= payload (:payload result)))
          (is (= (vec (.getBytes ^String payload StandardCharsets/UTF_8))
                 (vec (:payload-bytes result))))
          (is (= (:alg opts) (get-in result [:header :alg])))
          (is (= (:enc opts) (get-in result [:header :enc])))
          (is (= "text/plain" (get-in result [:header :cty])))))))
  (testing "defaults"
    (let [key (jwk/generate :rsa {:kid "rsa-default"})
          compact (jwe/encrypt key "hello")]
      (is (= {:alg :rsa-oaep-256 :enc :a256gcm :kid "rsa-default"}
             (jwe/header compact)))
      (is (= "hello" (:payload (jwe/decrypt key compact)))))))

(deftest pbes2-round-trips
  (doseq [alg [:pbes2-hs256+a128kw
               :pbes2-hs384+a192kw
               :pbes2-hs512+a256kw]]
    (testing alg
      (let [compact (jwe/encrypt "correct horse battery staple"
                                 "password protected"
                                 {:alg alg
                                  :enc :a256gcm
                                  :salt-length 16
                                  :iteration-count 1000})]
        (is (= "password protected"
               (:payload (jwe/decrypt "correct horse battery staple" compact))))))))

(deftest ecdh-1pu-round-trips
  (let [sender (jwk/generate :ec {:curve :p-256 :kid "sender"})
        recipient (jwk/generate :ec {:curve :p-256 :kid "recipient"})
        encrypt-keys {:sender sender :recipient (jwk/public-jwk recipient)}
        decrypt-keys {:sender (jwk/public-jwk sender) :recipient recipient}]
    (doseq [alg [:ecdh-1pu
                 :ecdh-1pu+a128kw
                 :ecdh-1pu+a192kw
                 :ecdh-1pu+a256kw]]
      (testing alg
        (let [compact (jwe/encrypt encrypt-keys "authenticated" {:alg alg :enc :a256cbc-hs512})]
          (is (= "authenticated" (:payload (jwe/decrypt decrypt-keys compact))))))))
  (testing "X25519"
    (let [sender (jwk/generate :okp {:curve :x25519 :kid "sender-x"})
          recipient (jwk/generate :okp {:curve :x25519 :kid "recipient-x"})
          compact (jwe/encrypt {:sender sender :recipient (jwk/public-jwk recipient)}
                               "authenticated x25519"
                               {:alg :ecdh-1pu+a256kw :enc :a256cbc-hs512})]
      (is (= "authenticated x25519"
             (:payload (jwe/decrypt {:sender (jwk/public-jwk sender)
                                     :recipient recipient}
                                    compact)))))))

(deftest xc20p-round-trip
  (let [key (jwk/generate :rsa {:kid "xc20p"})
        compact (jwe/encrypt key "extended nonce" {:alg :rsa-oaep-256 :enc :xc20p})
        result (jwe/decrypt key compact)]
    (is (= "extended nonce" (:payload result)))
    (is (= :xc20p (get-in result [:header :enc])))))

(deftest binary-payloads-return-bytes
  (let [key (jwk/generate :oct {:size 256})
        bytes (byte-array [0 1 2 -1])
        result (jwe/decrypt key (jwe/encrypt key bytes {:alg :dir}))]
    (is (= [0 1 2 -1] (vec (:payload-bytes result))))
    (is (= "\u0000\u0001\u0002�" (:payload result)))))

(deftest failures-are-ex-info
  (let [key (jwk/generate :oct {:size 256})
        other (jwk/generate :oct {:size 256})
        compact (jwe/encrypt key "hello" {:alg :dir})
        tampered (str compact "x")]
    (is (= :decryption-failure
           (:jose/error (thrown-data #(jwe/decrypt other compact)))))
    (is (= :decryption-failure
           (:jose/error (thrown-data #(jwe/decrypt key tampered)))))
    (is (= :parse-failure
           (:jose/error (thrown-data #(jwe/decrypt key "not-a-jwe")))))
    (is (= :invalid-option
           (:jose/error (thrown-data #(jwe/encrypt key "hello" {:rsa1-5 true})))))
    (is (str/includes? (ex-message (thrown #(jwe/encrypt key "hello" {:rsa1-5 true})))
                       ":rsa-oaep-256"))
    (is (= :invalid-option
           (:jose/error (thrown-data #(jwe/encrypt key "hello" {:alg :rsa1-5})))))
    (is (str/includes? (ex-message (thrown #(jwe/encrypt key "hello" {:alg :rsa1-5})))
                       ":rsa-oaep-256"))
    (is (= :key-length
           (:jose/error (thrown-data #(jwe/encrypt (jwk/generate :oct {:size 128})
                                                   "hello"
                                                   {:alg :a256kw})))))))
