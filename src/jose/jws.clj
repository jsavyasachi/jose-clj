(ns jose.jws
  (:require [clojure.string :as str]
            [jose.jwk :as jwk])
  (:import (com.nimbusds.jose JOSEException JWSAlgorithm JWSHeader JWSHeader$Builder JWSObject JWSProvider Payload)
           (com.nimbusds.jose.crypto ECDSASigner ECDSAVerifier Ed25519Signer Ed25519Verifier
                                      MACSigner MACVerifier RSASSASigner RSASSAVerifier)
           (com.nimbusds.jose.jwk Curve ECKey JWK KeyType OctetKeyPair OctetSequenceKey RSAKey)
           (java.nio.charset StandardCharsets)
           (java.security Provider Security)
           (java.text ParseException)
           (java.util List Map)))

(set! *warn-on-reflection* true)

(def ^:private sign-options #{:alg :kid :headers})

(def ^:private alg-names
  {:hs256 "HS256"
   :hs384 "HS384"
   :hs512 "HS512"
   :rs256 "RS256"
   :rs384 "RS384"
   :rs512 "RS512"
   :ps256 "PS256"
   :ps384 "PS384"
   :ps512 "PS512"
   :es256 "ES256"
   :es256k "ES256K"
   :es384 "ES384"
   :es512 "ES512"
   :eddsa "EdDSA"})

(def ^:private name-algs
  (into {} (map (fn [[k v]] [v k]) alg-names)))

(defn- jose-ex
  [error message cause data]
  (ex-info message (assoc data :jose/error error) cause))

(defn- invalid-option!
  [option]
  (throw (ex-info (str "Invalid option " option)
                  {:jose/error :invalid-option
                   :option option})))

(defn- validate-options!
  [opts]
  (doseq [option (keys opts)]
    (when-not (contains? sign-options option)
      (invalid-option! option))))

(defn- algorithm
  ^JWSAlgorithm [alg]
  (cond
    (instance? JWSAlgorithm alg) alg
    (keyword? alg) (JWSAlgorithm/parse ^String (get alg-names alg (str/upper-case (name alg))))
    (string? alg) (JWSAlgorithm/parse ^String alg)
    :else (invalid-option! :alg)))

(defn- alg-keyword
  [alg]
  (let [name (str alg)]
    (get name-algs name (keyword (str/lower-case name)))))

(defn- default-alg
  [^JWK key]
  (let [key-type (.getKeyType key)]
    (cond
      (= KeyType/RSA key-type) :rs256
      (= KeyType/OCT key-type) :hs256
      (= KeyType/OKP key-type) :eddsa
      (= KeyType/EC key-type) (let [curve (.getCurve (.toECKey key))]
                                (cond
                                  (= Curve/P_256 curve) :es256
                                  (= Curve/SECP256K1 curve) :es256k
                                  (= Curve/P_256K curve) :es256k
                                  (= Curve/P_384 curve) :es384
                                  (= Curve/P_521 curve) :es512
                                  :else (invalid-option! :alg)))
      :else (invalid-option! :alg))))

(defn- stringify-json-value
  [x]
  (cond
    (keyword? x) (name x)
    (map? x) (into {} (map (fn [[k v]]
                             [(name k) (stringify-json-value v)])
                           x))
    (sequential? x) (mapv stringify-json-value x)
    :else x))

(defn- keywordize-json-value
  [x]
  (cond
    (instance? Map x) (into {} (map (fn [[k v]]
                                      [(keyword k) (keywordize-json-value v)])
                                    x))
    (instance? List x) (mapv keywordize-json-value x)
    :else x))

(defn- header-map
  [^JWSHeader header]
  (update (keywordize-json-value (.toJSONObject header)) :alg alg-keyword))

(defn- ->payload
  ^Payload [payload]
  (cond
    (string? payload) (Payload. ^String payload)
    (bytes? payload) (Payload. ^bytes payload)
    :else (throw (ex-info "Expected string or bytes payload"
                          {:jose/error :invalid-option
                           :option :payload}))))

(defn- bouncy-castle-provider
  ^Provider []
  (or (Security/getProvider "BC")
      (try
        (let [provider (clojure.lang.Reflector/invokeConstructor
                        (Class/forName "org.bouncycastle.jce.provider.BouncyCastleProvider")
                        (object-array 0))]
          (Security/addProvider ^Provider provider)
          ^Provider provider)
        (catch ClassNotFoundException _
          nil))))

(defn- with-optional-ec-provider
  [provider ^ECKey key]
  (when (#{Curve/SECP256K1 Curve/P_256K} (.getCurve key))
    (when-let [bc (bouncy-castle-provider)]
      (.setProvider (.getJCAContext ^JWSProvider provider) bc)))
  provider)

(defn- signer
  [^JWK key]
  (let [key-type (.getKeyType key)]
    (cond
      (= KeyType/RSA key-type) (RSASSASigner. ^RSAKey (.toRSAKey key))
      (= KeyType/EC key-type) (let [ec-key (.toECKey key)]
                                (with-optional-ec-provider
                                  (ECDSASigner. ^ECKey ec-key)
                                  ec-key))
      (= KeyType/OCT key-type) (MACSigner. ^OctetSequenceKey (.toOctetSequenceKey key))
      (= KeyType/OKP key-type) (try
                                 (Ed25519Signer. ^OctetKeyPair (.toOctetKeyPair key))
                                 (catch NoClassDefFoundError e
                                   (throw (jose-ex :missing-optional-dep
                                                   "Missing optional Tink dependency"
                                                   e
                                                   {:dep "com.google.crypto.tink/tink"}))))
      :else (invalid-option! :alg))))

(defn- public-key
  ^JWK [^JWK key]
  (or (jwk/public-jwk key) key))

(defn- verifier
  [^JWK key]
  (let [key (public-key key)
        key-type (.getKeyType key)]
    (cond
      (= KeyType/RSA key-type) (RSASSAVerifier. ^RSAKey (.toRSAKey key))
      (= KeyType/EC key-type) (let [ec-key (.toECKey key)]
                                (with-optional-ec-provider
                                  (ECDSAVerifier. ^ECKey ec-key)
                                  ec-key))
      (= KeyType/OCT key-type) (MACVerifier. ^OctetSequenceKey (.toOctetSequenceKey key))
      (= KeyType/OKP key-type) (try
                                 (Ed25519Verifier. ^OctetKeyPair (.toOctetKeyPair key))
                                 (catch NoClassDefFoundError e
                                   (throw (jose-ex :missing-optional-dep
                                                   "Missing optional Tink dependency"
                                                   e
                                                   {:dep "com.google.crypto.tink/tink"}))))
      :else (invalid-option! :alg))))

(defn- jws-object
  ^JWSObject [compact]
  (try
    (JWSObject/parse ^String compact)
    (catch ParseException e
      (throw (jose-ex :parse-failure "Failed to parse JWS" e {})))
    (catch RuntimeException e
      (throw (jose-ex :parse-failure "Failed to parse JWS" e {})))))

(defn- apply-header!
  [^JWSHeader$Builder builder k v]
  (case k
    :cty (.contentType builder (str v))
    (.customParam builder (name k) (stringify-json-value v))))

(defn sign
  "Signs a string or byte-array payload and returns a compact JWS string."
  (^String [key payload-value]
   (sign key payload-value {}))
  (^String [key payload-value opts]
   (validate-options! opts)
   (try
     (let [^JWK key (jwk/parse key)
           alg (algorithm (:alg opts (default-alg key)))
           ^JWSHeader$Builder builder (JWSHeader$Builder. alg)
           kid (if (contains? opts :kid) (:kid opts) (.getKeyID key))]
       (doseq [[k v] (:headers opts)]
         (apply-header! builder k v))
       (when kid
         (.keyID builder kid))
       (let [jws (JWSObject. (.build builder) (->payload payload-value))]
         (.sign jws (signer key))
         (.serialize jws)))
     (catch JOSEException e
       (throw (jose-ex :sign-failure "Failed to sign JWS" e {}))))))

(defn verify
  "Verifies a compact JWS and returns {:payload string :payload-bytes bytes :header map}."
  [key compact]
  (try
    (let [jws (jws-object compact)
          ok? (.verify jws (verifier (jwk/parse key)))]
      (when-not ok?
        (throw (jose-ex :invalid-signature "Invalid JWS signature" nil {})))
      (let [^Payload payload (.getPayload jws)
            bytes (.toBytes payload)]
        {:payload (String. ^bytes bytes StandardCharsets/UTF_8)
         :payload-bytes bytes
         :header (header-map (.getHeader jws))}))
    (catch JOSEException e
      (throw (jose-ex :invalid-signature "Invalid JWS signature" e {})))))

(defn header
  "Returns the unverified compact JWS header as a Clojure map."
  [compact]
  (header-map (.getHeader (jws-object compact))))
