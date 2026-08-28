(ns jose.jwk-test
  (:require [clojure.test :refer [deftest is testing]]
            [jose.jwk :as jwk]
            [jose.jwks :as jwks])
  (:import (clojure.lang ExceptionInfo)
           (com.nimbusds.jose.jwk JWK JWKSet)
           (java.io ByteArrayInputStream File FileInputStream)
           (java.nio.charset StandardCharsets)
           (java.nio.file Files)
           (java.security Key KeyStore KeyPairGenerator PrivateKey PublicKey Security SecureRandom Signature)
           (javax.crypto KeyAgreement)
           (java.time Instant)
           (java.util Date)))

(defn generated-multi-keystore
  []
  (let [directory (Files/createTempDirectory "jose-clj-multi-keystore-"
                                              (make-array java.nio.file.attribute.FileAttribute 0))
        path (.resolve directory "test.jks")
        keytool (str (System/getProperty "java.home") "/bin/keytool")
        commands [["one" "onepass"] ["two" "twopass"]]]
    (doseq [[alias password] commands]
      (let [process (-> (ProcessBuilder.
                         [keytool "-genkeypair" "-alias" alias "-keyalg" "RSA"
                          "-keysize" "2048" "-dname" (str "CN=" alias)
                          "-validity" "1" "-storetype" "JKS"
                          "-keystore" (str path) "-storepass" "storepass"
                          "-keypass" password "-noprompt"])
                        (.redirectErrorStream true)
                        (.start))]
        (.readAllBytes (.getInputStream process))
        (when-not (zero? (.waitFor process))
          (throw (ex-info "keytool failed" {:alias alias})))))
    (let [keystore (KeyStore/getInstance "JKS")]
      (with-open [input (FileInputStream. (.toFile path))]
        (.load keystore input (.toCharArray "storepass")))
      keystore)))

;; This test vector is from RFC 7638 section 3.1.
(def rfc-7638-rsa-jwk
  {:kty "RSA"
   :n "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
   :e "AQAB"
   :alg "RS256"
   :kid "2011-04-29"})

;; This test vector is from RFC 8037 appendix A.3.
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

(deftest generate-accepts-jca-options
  (let [random-a (SecureRandom/getInstance "SHA1PRNG")
        random-b (SecureRandom/getInstance "SHA1PRNG")
        ec-random-a (SecureRandom/getInstance "SHA1PRNG")
        ec-random-b (SecureRandom/getInstance "SHA1PRNG")
        okp-random-a (SecureRandom/getInstance "SHA1PRNG")
        okp-random-b (SecureRandom/getInstance "SHA1PRNG")
        seed (.getBytes "jose-clj-test-seed" StandardCharsets/UTF_8)
        _ (.setSeed random-a seed)
        _ (.setSeed random-b seed)
        _ (.setSeed ec-random-a seed)
        _ (.setSeed ec-random-b seed)
        _ (.setSeed okp-random-a seed)
        _ (.setSeed okp-random-b seed)
        key-store (doto (KeyStore/getInstance "PKCS12")
                    (.load nil nil))
        provider (Security/getProvider "SunRsaSign")
        oct-a (jwk/generate :oct {:size 256 :secure-random random-a})
        oct-b (jwk/generate :oct {:size 256 :secure-random random-b})
        ec-a (jwk/generate :ec {:curve :p-256 :secure-random ec-random-a})
        ec-b (jwk/generate :ec {:curve :p-256 :secure-random ec-random-b})
        okp-a (jwk/generate :okp {:curve :ed25519 :secure-random okp-random-a})
        okp-b (jwk/generate :okp {:curve :ed25519 :secure-random okp-random-b})
        rsa (jwk/generate :rsa {:size 2048 :provider provider})
        stored (jwk/generate :oct {:size 256 :key-store key-store})]
    (is (= (jwk/->map oct-a) (jwk/->map oct-b)))
    (is (= (jwk/->map ec-a) (jwk/->map ec-b)))
    (is (= (jwk/->map okp-a) (jwk/->map okp-b)))
    (is (= :rsa (jwk/key-type rsa)))
    (is (identical? key-store (.getKeyStore stored)))))

(deftest generate-rejects-ignored-jca-options
  (doseq [[kind opts option] [[:oct {:provider (Security/getProvider "SunRsaSign")} :provider]
                             [:okp {:key-store (KeyStore/getInstance "PKCS12")} :key-store]
                             [:okp {:curve :x25519
                                    :secure-random (SecureRandom.)} :secure-random]]]
    (testing [kind option]
      (let [thrown (try
                     (jwk/generate kind opts)
                     nil
                     (catch ExceptionInfo e
                       e))]
        (is (= :invalid-option (:jose/error (ex-data thrown))))
        (is (= option (:option (ex-data thrown))))))))

(deftest generate-round-trips-complete-metadata
  (let [generated (jwk/generate :rsa
                                {:kid "metadata"
                                 :use :sig
                                 :alg :rs256
                                 :key-ops [:sign :verify]
                                 :x5u "https://example.test/cert.pem"
                                 :x5t "AQID"
                                 :x5t#S256 "BAUG"
                                 :iat (Instant/ofEpochSecond 100)
                                 :nbf (Date. 200000)
                                 :exp 300
                                 :revoked {:at 400 :reason :compromised}})
        generated-map (jwk/->map generated)
        metadata (select-keys generated-map
                              [:kid :use :alg :x5u :x5t :x5t#S256
                               :iat :nbf :exp :revoked])]
    (is (= {:kid "metadata"
            :use "sig"
            :alg "RS256"
            :x5u "https://example.test/cert.pem"
            :x5t "AQID"
            :x5t#S256 "BAUG"
            :iat 100
            :nbf 200
            :exp 300
            :revoked {:revoked_at 400 :reason "compromised"}}
           metadata))
    (is (= #{"sign" "verify"} (set (:key_ops generated-map))))))

(deftest metadata-accessors-return-clojure-values
  (let [generated (jwk/generate :rsa
                                {:kid "metadata"
                                 :use :sig
                                 :alg :rs256
                                 :key-ops [:sign :verify]
                                 :x5u "https://example.test/cert.pem"
                                 :x5t "BwgJ"
                                 :x5t#S256 "CwwN"
                                 :iat (Instant/ofEpochSecond 100)
                                 :nbf (Instant/ofEpochSecond 200)
                                 :exp (Instant/ofEpochSecond 300)})]
    (is (= :sig (jwk/key-use generated)))
    (is (= #{:sign :verify} (jwk/key-operations generated)))
    (is (= :rs256 (jwk/algorithm generated)))
    (is (= "metadata" (jwk/key-id generated)))
    (is (= (Instant/ofEpochSecond 100) (jwk/issue-time generated)))
    (is (= (Instant/ofEpochSecond 200) (jwk/not-before-time generated)))
    (is (= (Instant/ofEpochSecond 300) (jwk/expiration-time generated)))
    (is (= "https://example.test/cert.pem" (jwk/x509-cert-url generated)))
    (is (nil? (jwk/x509-cert-chain generated)))
    (is (= "BwgJ" (jwk/x509-cert-thumbprint generated)))
    (is (= "CwwN" (jwk/x509-cert-sha256-thumbprint generated)))))

(deftest thumbprint-uri-is-rfc-9278-jkt-uri
  (let [thumbprint (jwk/thumbprint rfc-7638-rsa-jwk)]
    (is (= (str "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" thumbprint)
           (jwk/thumbprint-uri rfc-7638-rsa-jwk)))))

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

(deftest advanced-jwk-set-operations
  (let [rsa (jwk/generate :rsa {:kid "rsa"})
        ec (jwk/generate :ec {:kid "ec" :curve :p-256})
        oct (jwk/generate :oct {:kid "oct"})
        jwks (jwk/jwk-set [rsa ec oct] {:issuer "example"})
        public-set (jwk/public-jwk-set jwks)
        filtered (jwk/filter-set jwks (jwks/matcher {:kty :ec}))]
    (is (jwk/set-contains? jwks (jwk/public-jwk rsa)))
    (is (not (jwk/set-contains? jwks (jwk/generate :rsa))))
    (is (= ["ec"] (mapv jwk/key-id (.getKeys filtered))))
    (is (= {:issuer "example"} (jwk/set-members jwks)))
    (is (= {:issuer "example"} (jwk/set-members public-set)))
    (is (= #{"rsa" "ec"} (set (map jwk/key-id (.getKeys public-set)))))
    (is (every? (complement jwk/private?) (.getKeys public-set)))
    (is (every? #(not-any? (partial contains? %)
                           [:d :p :q :dp :dq :qi :oth :k])
                (jwk/set->maps public-set)))))

(deftest loads-jwk-sets-from-file-stream-and-string
  (let [jwks (jwk/jwk-set [(jwk/generate :rsa {:kid "loaded"})]
                          {:issuer "example"})
        json (jwk/set->json jwks {:private? true})
        file (.toFile (Files/createTempFile "jose-clj-jwks-" ".json"
                                             (make-array java.nio.file.attribute.FileAttribute 0)))
        bytes (.getBytes json StandardCharsets/UTF_8)]
    (spit file json)
    (doseq [loaded [(jwk/load-set ^File file)
                    (jwk/load-set (ByteArrayInputStream. bytes))
                    (jwk/load-set json)]]
      (is (= ["loaded"] (mapv jwk/key-id (.getKeys ^JWKSet loaded))))
      (is (= {:issuer "example"} (jwk/set-members loaded))))))

(deftest jwks-convert-to-java-keys
  (doseq [[kind opts] [[:rsa {:size 2048}]
                       [:ec {:curve :p-256}]
                       [:okp {:curve :ed25519}]
                       [:oct {:size 256}]]]
    (testing kind
      (let [private (jwk/generate kind opts)
            public (jwk/public-jwk private)
            to-java-private-key (resolve 'jose.jwk/to-java-private-key)
            private-key (if (= :oct kind)
                          (first (jwk/to-java-keys private))
                          (when to-java-private-key (to-java-private-key private)))
            public-key (when public (first (jwk/to-java-keys public))) ]
        (is (some? to-java-private-key))
      (is (instance? Key private-key))
        (when public
          (is (instance? Key public-key))
          (is (= (.getAlgorithm ^Key private-key) (.getAlgorithm ^Key public-key))))))))

(deftest mixed-jwk-collections-do-not-drop-okp-keys
  (let [rsa (jwk/generate :rsa {:size 2048})
        okp (jwk/generate :okp {:curve :ed25519})
        keys (jwk/to-java-keys [rsa okp])]
    (is (= 4 (count keys)))
    (is (= #{"RSA" "EdDSA"} (set (map #(.getAlgorithm ^Key %) keys))))))

(deftest okp-java-keys-work-with-jdk-crypto
  (let [ed (jwk/generate :okp {:curve :ed25519})
        [ed-public ed-private] (jwk/to-java-keys ed)
        message (.getBytes "jose-clj" StandardCharsets/UTF_8)
        signature (doto (Signature/getInstance "Ed25519")
                    (.initSign ^PrivateKey ed-private)
                    (.update message))
        bytes (.sign signature)]
    (is (.verify (doto (Signature/getInstance "Ed25519")
                   (.initVerify ^PublicKey ed-public)
                   (.update message)) bytes)))
  (let [first-key (jwk/generate :okp {:curve :x25519})
        second-key (jwk/generate :okp {:curve :x25519})
        [first-public first-private] (jwk/to-java-keys first-key)
        [second-public second-private] (jwk/to-java-keys second-key)
        first-secret (doto (KeyAgreement/getInstance "X25519")
                       (.init ^PrivateKey first-private)
                       (.doPhase ^PublicKey second-public true))
        second-secret (doto (KeyAgreement/getInstance "X25519")
                        (.init ^PrivateKey second-private)
                        (.doPhase ^PublicKey first-public true))]
    (is (= (seq (.generateSecret first-secret))
           (seq (.generateSecret second-secret))))))

(deftest keystore-loads-with-per-alias-passwords
  (let [keystore (generated-multi-keystore)
        _ (.setCertificateEntry keystore "trusted" (.getCertificate keystore "one"))
        loaded (jwk/keystore->jwks keystore {"one" "onepass" "two" "twopass"})]
    (is (instance? JWKSet loaded))
    (is (= #{"one" "two"} (set (map jwk/key-id (.getKeys loaded)))))
    (let [thrown (try
                   (jwk/keystore->jwks keystore {"one" "wrong" "two" "twopass"})
                   nil
                   (catch ExceptionInfo e e))]
      (is (= :key-import-failure (:jose/error (ex-data thrown))))
      (is (= "one" (:alias (ex-data thrown)))))))
