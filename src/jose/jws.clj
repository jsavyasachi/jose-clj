(ns jose.jws
  (:require [clojure.string :as str]
            [jose.jwk :as jwk]
            [jose.jwks :as jwks])
  (:import (com.nimbusds.jose JOSEException JWSAlgorithm JWSHeader JWSHeader$Builder JWSObject JWSProvider Payload)
           (com.nimbusds.jose.crypto ECDSASigner ECDSAVerifier Ed25519Signer Ed25519Verifier
                                      MACSigner MACVerifier RSASSASigner RSASSAVerifier)
           (com.nimbusds.jose.jwk Curve ECKey JWK KeyType OctetKeyPair OctetSequenceKey RSAKey)
           (java.nio.charset StandardCharsets)
           (java.security Provider Security)
           (java.text ParseException)
           (java.util HashSet List Map)))

(set! *warn-on-reflection* true)

(def ^:private sign-options #{:alg :kid :headers :detached? :b64?})
(def ^:private verify-options #{:alg :algs :typ :cty :crit})

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

(defn- validate-verify-options!
  [opts]
  (doseq [option (keys opts)]
    (when-not (contains? verify-options option)
      (invalid-option! option)))
  (when-not (or (contains? opts :alg) (contains? opts :algs))
    (throw (jose-ex :algorithm-unspecified
                    "Expected JWS algorithm is required; pass :algs"
                    nil
                    {:option :algs}))))

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

(defn- fail!
  [error message data]
  (throw (jose-ex error message nil data)))

(defn- algorithm-name
  [alg]
  (str (algorithm alg)))

(defn- validate-verification-policy!
  [^JWSHeader header opts]
  (let [actual-alg (str (.getAlgorithm header))
        actual-typ (some-> (.getType header) str)
        actual-cty (.getContentType header)
        critical (set (.getCriticalParams header))]
    (when (or (= "none" (str/lower-case actual-alg))
              (and (contains? opts :alg)
                   (not= actual-alg (algorithm-name (:alg opts))))
              (and (contains? opts :algs)
                   (not= :any (:algs opts))
                   (not (contains? (set (map algorithm-name (:algs opts))) actual-alg))))
      (fail! :algorithm-not-allowed "JWS algorithm is not allowed" {:alg (alg-keyword actual-alg)}))
    (when (and (contains? opts :typ) (not= (str (:typ opts)) actual-typ))
      (fail! :header-mismatch "JWS typ header does not match" {:header :typ
                                                                :expected (str (:typ opts))
                                                                :actual actual-typ}))
    (when (and (contains? opts :cty) (not= (str (:cty opts)) actual-cty))
      (fail! :header-mismatch "JWS cty header does not match" {:header :cty
                                                                :expected (str (:cty opts))
                                                                :actual actual-cty}))
    (when (contains? opts :crit)
      (let [understood (set (map #(if (keyword? %) (name %) (str %)) (:crit opts)))
            unsupported (seq (remove understood critical))]
        (when unsupported
          (fail! :unsupported-critical-header
                 "JWS contains unsupported critical headers"
                 {:headers (set unsupported)}))))))

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
    (let [jws (JWSObject/parse ^String compact)
          header (.getHeader jws)]
      (if (and (false? (.isBase64URLEncodePayload header))
               (string? compact))
        (let [segments (str/split compact #"\." -1)]
          (if (and (= 3 (count segments))
                   (not (str/blank? (second segments))))
            (JWSObject/parse ^String (str (first segments) ".." (nth segments 2))
                             (Payload. ^String (second segments)))
            jws))
        jws))
    (catch ParseException e
      (throw (jose-ex :parse-failure "Failed to parse JWS" e {})))
    (catch RuntimeException e
      (throw (jose-ex :parse-failure "Failed to parse JWS" e {})))))

(defn- detached-jws-object
  ^JWSObject [compact payload]
  (try
    (JWSObject/parse ^String compact (->payload payload))
    (catch ParseException e
      (throw (jose-ex :parse-failure "Failed to parse JWS" e {})))
    (catch RuntimeException e
      (throw (jose-ex :parse-failure "Failed to parse JWS" e {})))))

(defn- apply-header!
  [^JWSHeader$Builder builder k v]
  (case k
    :cty (.contentType builder (str v))
    (.customParam builder (name k) (stringify-json-value v))))

(defn- string-set
  ^java.util.Set [xs]
  (let [set (HashSet.)]
    (doseq [x xs]
      (.add set (str x)))
    set))

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
       (when (false? (:b64? opts true))
         (.base64URLEncodePayload builder false)
         (.criticalParams builder (string-set ["b64"])))
       (when kid
         (.keyID builder kid))
       (let [jws (JWSObject. (.build builder) (->payload payload-value))]
         (.sign jws (signer key))
         (.serialize jws (boolean (:detached? opts false)))))
     (catch JOSEException e
       (throw (jose-ex :sign-failure "Failed to sign JWS" e {}))))))

(defn verify
  "Verifies a compact JWS and returns {:payload string :payload-bytes bytes :header map}.

  :alg or :algs is required and constrains accepted algorithms. :typ and :cty
  require matching headers. :crit names understood critical headers. Pass
  {:algs :any} to unsafely accept any signed algorithm supported by the key.
  alg:none is always rejected."
  ([key compact]
   (verify key compact {}))
  ([key compact opts]
   (validate-verify-options! opts)
   (try
     (let [jws (jws-object compact)]
       (validate-verification-policy! (.getHeader jws) opts)
       (when-not (.verify jws (verifier (jwk/parse key)))
         (throw (jose-ex :invalid-signature "Invalid JWS signature" nil {})))
       (let [^Payload payload (.getPayload jws)
             bytes (.toBytes payload)]
         {:payload (String. ^bytes bytes StandardCharsets/UTF_8)
          :payload-bytes bytes
          :header (header-map (.getHeader jws))}))
     (catch JOSEException e
       (throw (jose-ex :invalid-signature "Invalid JWS signature" e {}))))))

(defn verify-detached
  "Verifies a detached compact JWS with an out-of-band payload.

  Accepts the same required algorithm policy and optional header policy as verify."
  ([key compact payload]
   (verify-detached key compact payload {}))
  ([key compact payload opts]
   (validate-verify-options! opts)
   (try
     (let [jws (detached-jws-object compact payload)]
       (validate-verification-policy! (.getHeader jws) opts)
       (when-not (.verify jws (verifier (jwk/parse key)))
         (throw (jose-ex :invalid-signature "Invalid JWS signature" nil {})))
       (let [^Payload payload (.getPayload jws)
             bytes (.toBytes payload)]
         {:payload (String. ^bytes bytes StandardCharsets/UTF_8)
          :payload-bytes bytes
          :header (header-map (.getHeader jws))}))
     (catch JOSEException e
       (throw (jose-ex :invalid-signature "Invalid JWS signature" e {}))))))

(defn header
  "Returns the unverified compact JWS header as a Clojure map."
  [compact]
  (header-map (.getHeader (jws-object compact))))

(defn- select-jwks-key
  [source compact]
  (let [{:keys [kid alg]} (header compact)
        keys (jwks/get-keys source (cond-> {:alg alg}
                                     kid (assoc :kid kid)))]
    (cond
      (empty? keys) (throw (jose-ex :key-not-found "No matching JWK found" nil {}))
      (and (nil? kid) (< 1 (count keys))) (throw (jose-ex :ambiguous-key "Multiple matching JWKs found" nil {}))
      :else (first keys))))

(defn verify-with-jwks
  "Selects a verification key from a JWKS source, then verifies a compact JWS."
  ([source compact]
   (verify-with-jwks source compact {}))
  ([source compact opts]
   (validate-verify-options! opts)
   (verify (select-jwks-key source compact) compact opts)))
