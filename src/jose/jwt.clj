(ns jose.jwt
  (:require [clojure.set :as set]
            [clojure.string :as str]
            [jose.jwe :as jwe]
            [jose.jwk :as jwk]
            [jose.jwks :as jwks])
  (:import (com.nimbusds.jose EncryptionMethod Header JOSEException JOSEObjectType JWEAlgorithm JWEHeader JWSAlgorithm JWSHeader JWSHeader$Builder JWSProvider)
           (com.nimbusds.jose.crypto ECDSASigner ECDSAVerifier Ed25519Signer Ed25519Verifier
                                      MACSigner MACVerifier RSASSASigner RSASSAVerifier)
           (com.nimbusds.jose.jwk Curve ECKey JWK KeyType OctetKeyPair OctetSequenceKey RSAKey)
           (com.nimbusds.jose.jwk.source JWKSource)
           (com.nimbusds.jose.proc BadJOSEException BadJWEException BadJWSException DefaultJOSEObjectTypeVerifier
                                   JWEDecryptionKeySelector JWEKeySelector JWSVerificationKeySelector SecurityContext)
           (com.nimbusds.jwt EncryptedJWT JWT JWTClaimsSet JWTClaimsSet$Builder JWTParser PlainJWT SignedJWT)
           (com.nimbusds.jwt.proc BadJWTException ConfigurableJWTProcessor DefaultJWTClaimsVerifier
                                  DefaultJWTProcessor ExpiredJWTException JWTClaimsSetVerifier)
           (java.security Provider Security)
           (java.text ParseException)
           (java.time Instant)
           (java.util ArrayList Date HashSet List Map Set)))

(set! *warn-on-reflection* true)

(deftype JWTContext [value]
  SecurityContext)

(def ^:private sign-options #{:alg :kid :headers :now-iat? :expires-in})
(def ^:private encrypt-options #{:alg :enc :kid :headers :now-iat? :expires-in})
(def ^:private jwe-options #{:alg :enc :kid :headers})
(def ^:private claim-verification-options
  #{:aud :iss :clock-skew :required :max-age :exact :prohibited :verifier})
(def ^:private verify-options (into claim-verification-options #{:alg :algs :typ :cty :crit}))
(def ^:private processor-options
  (into claim-verification-options
        #{:jws-alg :jws-algs :jwe-alg :jwe-algs :jwe-enc :jwe-encs :typ}))
(def ^:private registered-claims #{"iss" "sub" "aud" "exp" "nbf" "iat" "jti"})

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

(defn- jose-ex
  [error message cause data]
  (ex-info message (assoc data :jose/error error) cause))

(defn- invalid-option!
  [option]
  (throw (ex-info (str "Invalid option " option)
                  {:jose/error :invalid-option
                   :option option})))

(defn- validate-options!
  [allowed opts]
  (doseq [option (keys opts)]
    (when-not (contains? allowed option)
      (invalid-option! option))))

(defn- algorithm
  ^JWSAlgorithm [alg]
  (cond
    (instance? JWSAlgorithm alg) alg
    (keyword? alg) (JWSAlgorithm/parse ^String (get alg-names alg (str/upper-case (name alg))))
    (string? alg) (JWSAlgorithm/parse ^String alg)
    :else (invalid-option! :alg)))

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
  [^Header header]
  (cond-> (keywordize-json-value (.toJSONObject header))
    (.getAlgorithm header) (update :alg #(keyword (str/lower-case (str %))))
    (instance? JWEHeader header) (update :enc #(keyword (str/lower-case (str %))))))

(defn- parsed-jwt
  ^JWT [compact]
  (try
    (JWTParser/parse ^String compact)
    (catch ParseException e
      (throw (jose-ex :parse-failure "Failed to parse JWT" e {})))
    (catch RuntimeException e
      (throw (jose-ex :parse-failure "Failed to parse JWT" e {})))))

(defn parse
  "Inspects a compact JWT and returns its type and unverified header.

  This only parses attacker-controlled data. It does not verify a signature,
  decrypt content, validate claims, or establish trust."
  [compact]
  (let [jwt (parsed-jwt compact)]
    {:type (cond
             (instance? SignedJWT jwt) :signed
             (instance? EncryptedJWT jwt) :encrypted
             (instance? PlainJWT jwt) :plain)
     :header (header-map (.getHeader jwt))}))

(defn parse-type
  "Returns the unverified compact JWT type: :plain, :signed, or :encrypted.

  This is inspection-only and does not establish trust."
  [compact]
  (:type (parse compact)))

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

(defn- java-list
  ^List [xs]
  (let [list (ArrayList.)]
    (doseq [x xs]
      (.add list x))
    list))

(defn- instant
  ^Instant [x option]
  (cond
    (instance? Instant x) x
    (integer? x) (Instant/ofEpochSecond (long x))
    :else (invalid-option! option)))

(defn- date
  ^Date [x option]
  (Date/from (instant x option)))

(defn- apply-claim!
  [^JWTClaimsSet$Builder builder k v]
  (let [claim (name k)]
    (case claim
      "iss" (.issuer builder (str v))
      "sub" (.subject builder (str v))
      "aud" (if (sequential? v)
              (.audience builder (java-list (map str v)))
              (.audience builder (str v)))
      "exp" (.expirationTime builder (date v :exp))
      "nbf" (.notBeforeTime builder (date v :nbf))
      "iat" (.issueTime builder (date v :iat))
      "jti" (.jwtID builder (str v))
      (.claim builder claim (stringify-json-value v)))))

(defn- claims-set
  ^JWTClaimsSet [claims opts]
  (let [now (Instant/now)
        claims (cond-> claims
                 (:now-iat? opts) (assoc :iat now)
                 (contains? opts :expires-in) (assoc :exp (.plusSeconds now (long (:expires-in opts)))))
        builder (JWTClaimsSet$Builder.)]
    (doseq [[k v] claims]
      (apply-claim! builder k v))
    (.build builder)))

(defn- apply-header!
  [^JWSHeader$Builder builder k v]
  (case k
    :typ (.type builder (JOSEObjectType. (str v)))
    :cty (.contentType builder (str v))
    (.customParam builder (name k) (stringify-json-value v))))

(defn sign
  "Signs a JWT claims map and returns a compact JWS string."
  (^String [key claims]
   (sign key claims {}))
  (^String [key claims opts]
   (validate-options! sign-options opts)
   (try
     (let [^JWK key (jwk/parse key)
           alg (algorithm (:alg opts (default-alg key)))
           ^JWSHeader$Builder header-builder (JWSHeader$Builder. alg)
           kid (if (contains? opts :kid) (:kid opts) (.getKeyID key))]
       (doseq [[k v] (:headers opts)]
         (apply-header! header-builder k v))
       (when kid
         (.keyID header-builder kid))
       (let [jwt (SignedJWT. (.build header-builder) (claims-set claims opts))]
         (.sign jwt (signer key))
         (.serialize jwt)))
     (catch JOSEException e
       (throw (jose-ex :sign-failure "Failed to sign JWT" e {}))))))

(defn- signed-jwt
  ^SignedJWT [compact]
  (try
    (SignedJWT/parse ^String compact)
    (catch ParseException e
      (throw (jose-ex :parse-failure "Failed to parse JWT" e {})))
    (catch RuntimeException e
      (throw (jose-ex :parse-failure "Failed to parse JWT" e {})))))

(defn- claim-key
  [k]
  (if (contains? registered-claims k) (keyword k) k))

(defn- claim-value
  [k v]
  (cond
    (#{"exp" "nbf" "iat"} k) (.toInstant ^Date v)
    (= "aud" k) (vec v)
    :else v))

(defn- claims-map
  [^JWTClaimsSet claims]
  (into {} (map (fn [[k v]]
                  [(claim-key k) (claim-value k v)])
                (.getClaims claims))))

(defn- fail!
  [error message data]
  (throw (jose-ex error message nil data)))

(defn- validate-verify-options!
  [opts]
  (validate-options! verify-options opts)
  (when-not (or (contains? opts :alg) (contains? opts :algs))
    (fail! :algorithm-unspecified
           "Expected JWT algorithm is required; pass :algs"
           {:option :algs})))

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
      (fail! :algorithm-not-allowed "JWT algorithm is not allowed" {:alg actual-alg}))
    (when (and (contains? opts :typ) (not= (str (:typ opts)) actual-typ))
      (fail! :header-mismatch "JWT typ header does not match" {:header :typ
                                                                :expected (str (:typ opts))
                                                                :actual actual-typ}))
    (when (and (contains? opts :cty) (not= (str (:cty opts)) actual-cty))
      (fail! :header-mismatch "JWT cty header does not match" {:header :cty
                                                                :expected (str (:cty opts))
                                                                :actual actual-cty}))
    (when (contains? opts :crit)
      (let [understood (set (map #(if (keyword? %) (name %) (str %)) (:crit opts)))
            unsupported (seq (remove understood critical))]
        (when unsupported
          (fail! :unsupported-critical-header
                 "JWT contains unsupported critical headers"
                 {:headers (set unsupported)}))))))

(defn- claim-name
  [claim]
  (if (keyword? claim) (name claim) (str claim)))

(defn- java-set
  ^Set [xs]
  (HashSet. ^java.util.Collection (mapv claim-name xs)))

(defn- audiences
  [aud]
  (cond
    (nil? aud) nil
    (or (sequential? aud) (set? aud)) (java-set aud)
    :else (java-set [aud])))

(defn- exact-claims
  [opts]
  (cond-> (:exact opts {})
    (contains? opts :iss) (assoc :iss (:iss opts))))

(defn- default-claims-verifier
  ^DefaultJWTClaimsVerifier [opts]
  (let [verifier (DefaultJWTClaimsVerifier.
                  (audiences (:aud opts))
                  (claims-set (exact-claims opts) {})
                  (java-set (:required opts))
                  (java-set (:prohibited opts)))]
    (.setMaxClockSkew verifier (int (:clock-skew opts 0)))
    verifier))

(defn- verifier-failure
  [error message data]
  (BadJWTException. message (jose-ex error message nil data)))

(defn- verify-additional-claims!
  [claims context opts]
  (when (contains? opts :max-age)
    (let [iat (:iat claims)
          now (Instant/now)
          skew (long (:clock-skew opts 0))]
      (when-not iat
        (throw (verifier-failure :missing-claim
                                 "Missing required JWT claim"
                                 {:claim :iat})))
      (when (.isBefore ^Instant iat (.minusSeconds now (+ (long (:max-age opts)) skew)))
        (throw (verifier-failure :too-old
                                 "JWT exceeds maximum age"
                                 {:claim :iat :max-age (:max-age opts)})))))
  (when-let [custom (:verifier opts)]
    (try
      (let [context (if (instance? JWTContext context)
                      (.-value ^JWTContext context)
                      context)]
        (when-not (custom claims context)
          (throw (jose-ex :claim-verification-failure
                          "Custom JWT claims verifier rejected claims"
                          nil
                          {}))))
      (catch Exception e
        (throw (BadJWTException. "Custom JWT claims verification failed" e))))))

(defn claims-verifier
  "Returns a Nimbus JWTClaimsSetVerifier for a Clojure claims policy.

  :exact requires exact claim values. :aud accepts one audience or a collection
  where any match is accepted. :prohibited rejects named claims. :verifier is
  called with the normalized claims map and processor security context and must
  return truthy. Existing :iss, :required, :clock-skew, and :max-age options are
  also supported."
  ^JWTClaimsSetVerifier [opts]
  (validate-options! claim-verification-options opts)
  (when (and (contains? opts :verifier) (not (ifn? (:verifier opts))))
    (invalid-option! :verifier))
  (let [delegate (default-claims-verifier opts)]
    (reify JWTClaimsSetVerifier
      (verify [_ jwt-claims context]
        (.verify delegate jwt-claims context)
        (verify-additional-claims! (claims-map jwt-claims) context opts)))))

(defn- mismatch-entry
  [expected actual]
  (first (remove (fn [[claim value]] (= value (get actual claim))) expected)))

(defn- claims-verification-error
  [^BadJWTException error ^JWTClaimsSet jwt-claims opts]
  (let [cause (.getCause error)
        claims (claims-map jwt-claims)
        expected-aud (set (map str (or (some-> (:aud opts) audiences) [])))
        actual-aud (set (:aud claims))
        required (map claim-name (:required opts))
        missing (first (remove #(.containsKey (.getClaims jwt-claims) %) required))
        prohibited (first (filter #(.containsKey (.getClaims jwt-claims) %)
                                  (map claim-name (:prohibited opts))))
        expected (claims-map (claims-set (exact-claims opts) {}))
        mismatch (mismatch-entry expected claims)]
    (cond
      (instance? clojure.lang.ExceptionInfo cause) cause
      (instance? ExpiredJWTException error)
      (jose-ex :expired "JWT is expired" error {:claim :exp})
      (= "JWT before use time" (.getMessage error))
      (jose-ex :not-yet-valid "JWT is not yet valid" error {:claim :nbf})
      (and (contains? opts :aud) (empty? actual-aud))
      (jose-ex :missing-claim "Missing required JWT claim" error {:claim :aud})
      (and (seq expected-aud) (empty? (set/intersection expected-aud actual-aud)))
      (jose-ex :claim-mismatch "JWT audience does not match" error
               {:claim :aud :expected (:aud opts) :actual (:aud claims)})
      missing
      (jose-ex :missing-claim "Missing required JWT claim" error {:claim (claim-key missing)})
      prohibited
      (jose-ex :prohibited-claim "JWT contains a prohibited claim" error
               {:claim (claim-key prohibited)})
      mismatch
      (let [[claim expected-value] mismatch]
        (jose-ex :claim-mismatch "JWT claim does not match" error
                 {:claim claim :expected expected-value :actual (get claims claim)}))
      :else
      (jose-ex :claim-verification-failure "JWT claims verification failed" error {}))))

(defn verify-claims
  "Verifies a claims map or Nimbus JWTClaimsSet and returns normalized claims.

  The optional context is passed to :verifier."
  ([claims opts]
   (verify-claims claims nil opts))
  ([claims context opts]
   (let [jwt-claims (if (instance? JWTClaimsSet claims)
                      claims
                      (claims-set claims {}))]
     (try
       (.verify (claims-verifier opts)
                jwt-claims
                (if (or (nil? context) (instance? SecurityContext context))
                  context
                  (JWTContext. context)))
       (claims-map jwt-claims)
       (catch BadJWTException e
         (throw (claims-verification-error e jwt-claims opts)))))))

(defn- validated-claims
  [^JWTClaimsSet jwt-claims opts]
  (verify-claims jwt-claims (select-keys opts claim-verification-options)))

(defn- expected-values
  [opts singular plural]
  (when-not (or (contains? opts singular) (contains? opts plural))
    (fail! :algorithm-unspecified
           "Expected JWT algorithms are required"
           {:option plural}))
  (let [value (if (contains? opts plural) (get opts plural) (get opts singular))
        values (if (or (sequential? value) (set? value)) value [value])]
    (when (or (= :any value) (empty? values))
      (invalid-option! plural))
    values))

(defn- jwe-algorithm
  ^JWEAlgorithm [alg]
  (let [name (cond
               (instance? JWEAlgorithm alg) (str alg)
               (keyword? alg) (if (= :dir alg) "dir" (str/upper-case (name alg)))
               (string? alg) alg
               :else (invalid-option! :jwe-algs))]
    (when (#{"RSA1_5" "RSA1-5"} name)
      (invalid-option! :jwe-algs))
    (JWEAlgorithm/parse ^String name)))

(defn- encryption-method
  ^EncryptionMethod [enc]
  (let [name (cond
               (instance? EncryptionMethod enc) (str enc)
               (keyword? enc) (str/upper-case (name enc))
               (string? enc) enc
               :else (invalid-option! :jwe-encs))]
    (when (#{"A128CBC+HS256" "A256CBC+HS512"} name)
      (invalid-option! :jwe-encs))
    (EncryptionMethod/parse ^String name)))

(defn- expected-jws-algorithms
  ^Set [opts]
  (let [algorithms (mapv algorithm (expected-values opts :jws-alg :jws-algs))]
    (when (some #(= "none" (str/lower-case (str %))) algorithms)
      (invalid-option! :jws-algs))
    (HashSet. ^java.util.Collection algorithms)))

(defn- expected-jwe-algorithms
  [opts]
  (set (map jwe-algorithm (expected-values opts :jwe-alg :jwe-algs))))

(defn- expected-encryption-methods
  [opts]
  (set (map encryption-method (expected-values opts :jwe-enc :jwe-encs))))

(defn- jwk-source
  ^JWKSource [source]
  (cond
    (instance? JWKSource source) source
    (instance? JWKSource (:jwk-source source)) (:jwk-source source)
    :else (invalid-option! :source)))

(defn- jwe-key-selector
  ^JWEKeySelector [source allowed-algs allowed-encs]
  (reify JWEKeySelector
    (selectJWEKeys [_ header context]
      (if (and (contains? allowed-algs (.getAlgorithm ^JWEHeader header))
               (contains? allowed-encs (.getEncryptionMethod ^JWEHeader header)))
        (.selectJWEKeys (JWEDecryptionKeySelector. (.getAlgorithm ^JWEHeader header)
                                                  (.getEncryptionMethod ^JWEHeader header)
                                                  source)
                        header
                        context)
        (ArrayList.)))))

(defn- type-verifier
  ^DefaultJOSEObjectTypeVerifier [typ]
  (let [types (HashSet.)]
    (.add types (JOSEObjectType. (str typ)))
    (DefaultJOSEObjectTypeVerifier. ^Set types)))

(defn processor
  "Builds a Nimbus ConfigurableJWTProcessor from a JWKS source and policy.

  :jws-algs, :jwe-algs, and :jwe-encs are required allow-lists. Singular
  :jws-alg, :jwe-alg, and :jwe-enc forms are also accepted. :typ optionally
  requires an exact JOSE type on signed and encrypted layers. Plain JWTs are
  always rejected. Claims policy options are passed to claims-verifier."
  ^ConfigurableJWTProcessor [source opts]
  (validate-options! processor-options opts)
  (let [source (jwk-source source)
        jws-algs (expected-jws-algorithms opts)
        jwe-algs (expected-jwe-algorithms opts)
        jwe-encs (expected-encryption-methods opts)
        processor (DefaultJWTProcessor.)]
    (.setJWSKeySelector processor (JWSVerificationKeySelector. jws-algs source))
    (.setJWEKeySelector processor (jwe-key-selector source jwe-algs jwe-encs))
    (.setJWTClaimsSetVerifier processor
                             (claims-verifier (select-keys opts claim-verification-options)))
    (when (contains? opts :typ)
      (let [verifier (type-verifier (:typ opts))]
        (.setJWSTypeVerifier processor verifier)
        (.setJWETypeVerifier processor verifier)))
    processor))

(defn- validate-processor-header!
  [compact opts]
  (let [{:keys [type header]} (parse compact)]
    (when (= :plain type)
      (fail! :unsecured-jwt "Unsecured plain JWTs are rejected" {}))
    (when (contains? opts :typ)
      (when-not (= (str (:typ opts)) (:typ header))
        (fail! :header-mismatch "JWT typ header does not match"
               {:header :typ :expected (str (:typ opts)) :actual (:typ header)})))
    (case type
      :signed
      (let [allowed (expected-jws-algorithms opts)
            actual (algorithm (:alg header))]
        (when-not (contains? allowed actual)
          (fail! :algorithm-not-allowed "JWT algorithm is not allowed" {:alg (:alg header)})))

      :encrypted
      (let [allowed-algs (expected-jwe-algorithms opts)
            allowed-encs (expected-encryption-methods opts)
            actual-alg (jwe-algorithm (:alg header))
            actual-enc (encryption-method (:enc header))]
        (when-not (contains? allowed-algs actual-alg)
          (fail! :algorithm-not-allowed "JWT algorithm is not allowed" {:alg (:alg header)}))
        (when-not (contains? allowed-encs actual-enc)
          (fail! :encryption-method-not-allowed
                 "JWT encryption method is not allowed"
                 {:enc (:enc header)})))
      nil)))

(defn- processor-claims-error
  [^BadJWTException error]
  (let [cause (.getCause error)
        message (.getMessage error)]
    (cond
      (instance? clojure.lang.ExceptionInfo cause) cause
      (instance? ExpiredJWTException error) (jose-ex :expired "JWT is expired" error {:claim :exp})
      (= "JWT before use time" message) (jose-ex :not-yet-valid "JWT is not yet valid" error {:claim :nbf})
      (str/includes? message "missing required") (jose-ex :missing-claim message error {})
      (str/includes? message "prohibited") (jose-ex :prohibited-claim message error {})
      (str/includes? message "claim") (jose-ex :claim-mismatch message error {})
      (= "The payload is not a nested signed JWT" message)
      (jose-ex :not-a-nested-jwt message error {})
      :else (jose-ex :claim-verification-failure "JWT claims verification failed" error {}))))

(defn process
  "Processes a signed, encrypted, or nested compact JWT and returns claims.

  The policy requires explicit JWS, JWE, and content-encryption allow-lists.
  Plain JWTs and alg:none are always rejected. The optional context is passed
  to the claims verifier."
  ([source compact opts]
   (process source compact nil opts))
  ([source compact context opts]
   (let [processor (processor source opts)
         ^SecurityContext context (if (or (nil? context) (instance? SecurityContext context))
                                    context
                                    (JWTContext. context))]
     (validate-processor-header! compact opts)
     (try
       (claims-map (.process ^ConfigurableJWTProcessor processor ^String compact context))
       (catch BadJWTException e
         (throw (processor-claims-error e)))
       (catch BadJWSException e
         (throw (jose-ex :invalid-signature "Invalid JWT signature" e {})))
       (catch BadJWEException e
         (throw (jose-ex :decryption-failure "Failed to decrypt JWT" e {})))
       (catch BadJOSEException e
         (let [message (.getMessage e)]
           (throw (cond
                    (str/includes? message "typ (type)")
                    (jose-ex :header-mismatch "JWT typ header does not match" e {:header :typ})
                    :else
                    (jose-ex :key-not-found "No matching JWT key found" e {})))))
       (catch ParseException e
         (throw (jose-ex :parse-failure "Failed to parse JWT" e {})))
       (catch JOSEException e
         (throw (jose-ex :processing-failure "Failed to process JWT" e {})))))))

(defn verify
  "Verifies a compact signed JWT and returns claims.

  Registered claims are keyword keys. Custom claims keep their string keys.
  :exp, :nbf, and :iat return java.time.Instant values. :aud returns a vector.
  :alg or :algs is required and constrains accepted algorithms. :typ and :cty
  require matching headers. :crit names understood critical headers. :max-age
  limits token age by :iat. Pass {:algs :any} to unsafely accept any signed
  algorithm supported by the key. alg:none is always rejected."
  ([key compact]
   (verify key compact {}))
  ([key compact opts]
   (validate-verify-options! opts)
   (try
     (let [jwt (signed-jwt compact)
           header (.getHeader jwt)]
       (validate-verification-policy! header opts)
       (when-not (.verify jwt (verifier (jwk/parse key)))
         (throw (jose-ex :invalid-signature "Invalid JWT signature" nil {})))
       (validated-claims (.getJWTClaimsSet jwt) opts))
     (catch JOSEException e
       (throw (jose-ex :invalid-signature "Invalid JWT signature" e {})))
     (catch ParseException e
       (throw (jose-ex :parse-failure "Failed to parse JWT claims" e {}))))))

(defn- select-jwks-key
  [source compact]
  (let [jwt (signed-jwt compact)
        header (.getHeader jwt)
        kid (.getKeyID header)
        alg (.getAlgorithm header)
        keys (jwks/get-keys source (cond-> {:alg alg}
                                     kid (assoc :kid kid)))]
    (cond
      (empty? keys) (throw (jose-ex :key-not-found "No matching JWK found" nil {}))
      (and (nil? kid) (< 1 (count keys))) (throw (jose-ex :ambiguous-key "Multiple matching JWKs found" nil {}))
      :else (first keys))))

(defn verify-with-jwks
  "Selects a verification key from a JWKS source, then verifies a compact JWT."
  ([source compact]
   (verify-with-jwks source compact {}))
  ([source compact opts]
   (validate-verify-options! opts)
   (verify (select-jwks-key source compact) compact opts)))

(defn- parse-claims
  ^JWTClaimsSet [s]
  (try
    (JWTClaimsSet/parse ^String s)
    (catch ParseException e
      (throw (jose-ex :parse-failure "Failed to parse JWT claims" e {})))))

(defn- select-options
  [allowed opts]
  (select-keys opts allowed))

(defn encrypt
  "Encrypts a JWT claims map and returns a compact JWE string."
  (^String [key claims]
   (encrypt key claims {}))
  (^String [key claims opts]
   (validate-options! encrypt-options opts)
   (let [jwt-claims (claims-set claims opts)]
     (jwe/encrypt key (.toString jwt-claims) (select-options jwe-options opts)))))

(defn decrypt
  "Decrypts a compact encrypted JWT and returns validated claims."
  ([key compact]
   (decrypt key compact {}))
  ([key compact opts]
   (validate-options! claim-verification-options opts)
   (validated-claims (parse-claims (:payload (jwe/decrypt key compact))) opts)))

(defn sign-then-encrypt
  "Signs claims as a compact JWT, then encrypts the signed JWT as a nested JWE."
  [sign-key encrypt-key claims opts]
  (let [sign-opts (:sign-opts opts)
        encrypt-opts (:encrypt-opts opts)
        signed (sign sign-key claims sign-opts)
        headers (assoc (:headers encrypt-opts) :cty "JWT")]
    (jwe/encrypt encrypt-key signed (assoc encrypt-opts :headers headers))))

(defn decrypt-then-verify
  "Decrypts a nested JWE, then verifies the inner signed JWT."
  ([decrypt-key verify-key compact]
   (decrypt-then-verify decrypt-key verify-key compact {}))
  ([decrypt-key verify-key compact opts]
   (validate-verify-options! opts)
   (let [payload (:payload (jwe/decrypt decrypt-key compact))]
     (when-not (= 3 (count (str/split payload #"\.")))
       (fail! :not-a-nested-jwt "JWE payload is not a nested JWT" {}))
     (try
       (verify verify-key payload opts)
       (catch clojure.lang.ExceptionInfo e
         (if (= :parse-failure (:jose/error (ex-data e)))
           (throw (jose-ex :not-a-nested-jwt "JWE payload is not a nested JWT" e {}))
           (throw e)))))))

(defn claims
  "Returns unverified compact JWT claims.

  Registered claims are keyword keys. Custom claims keep their string keys.
  :exp, :nbf, and :iat return java.time.Instant values. :aud returns a vector."
  [compact]
  (try
    (claims-map (.getJWTClaimsSet (signed-jwt compact)))
    (catch ParseException e
      (throw (jose-ex :parse-failure "Failed to parse JWT claims" e {})))))
