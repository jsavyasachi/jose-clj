(ns jose.jwt
  (:require [clojure.string :as str]
            [jose.jwe :as jwe]
            [jose.jwk :as jwk])
  (:import (com.nimbusds.jose JOSEException JOSEObjectType JWSAlgorithm JWSHeader$Builder JWSProvider)
           (com.nimbusds.jose.crypto ECDSASigner ECDSAVerifier Ed25519Signer Ed25519Verifier
                                      MACSigner MACVerifier RSASSASigner RSASSAVerifier)
           (com.nimbusds.jose.jwk Curve ECKey JWK KeyType OctetKeyPair OctetSequenceKey RSAKey)
           (com.nimbusds.jwt JWTClaimsSet JWTClaimsSet$Builder SignedJWT)
           (java.security Provider Security)
           (java.text ParseException)
           (java.time Instant)
           (java.util ArrayList Date List)))

(set! *warn-on-reflection* true)

(def ^:private sign-options #{:alg :kid :headers :now-iat? :expires-in})
(def ^:private encrypt-options #{:alg :enc :kid :headers :now-iat? :expires-in})
(def ^:private jwe-options #{:alg :enc :kid :headers})
(def ^:private verify-options #{:aud :iss :clock-skew :required})
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

(defn- require-claim!
  [claims claim]
  (let [k (if (keyword? claim) claim (str claim))]
    (when-not (contains? claims k)
      (fail! :missing-claim "Missing required JWT claim" {:claim k}))))

(defn- validate-claims!
  [claims opts]
  (let [now (Instant/now)
        skew (long (:clock-skew opts 0))]
    (when-let [exp (:exp claims)]
      (when (.isBefore ^Instant exp (.minusSeconds now skew))
        (fail! :expired "JWT is expired" {:claim :exp})))
    (when-let [nbf (:nbf claims)]
      (when (.isAfter ^Instant nbf (.plusSeconds now skew))
        (fail! :not-yet-valid "JWT is not yet valid" {:claim :nbf})))
    (when-let [expected (:aud opts)]
      (when-not (some #{expected} (:aud claims))
        (fail! :claim-mismatch "JWT audience does not match" {:claim :aud
                                                              :expected expected
                                                              :actual (:aud claims)})))
    (when-let [expected (:iss opts)]
      (when-not (= expected (:iss claims))
        (fail! :claim-mismatch "JWT issuer does not match" {:claim :iss
                                                            :expected expected
                                                            :actual (:iss claims)})))
    (doseq [claim (:required opts)]
      (require-claim! claims claim))))

(defn- validated-claims
  [^JWTClaimsSet jwt-claims opts]
  (let [claims (claims-map jwt-claims)]
    (validate-claims! claims opts)
    claims))

(defn verify
  "Verifies a compact signed JWT and returns claims.

  Registered claims are keyword keys. Custom claims keep their string keys.
  :exp, :nbf, and :iat return java.time.Instant values. :aud returns a vector."
  ([key compact]
   (verify key compact {}))
  ([key compact opts]
   (validate-options! verify-options opts)
   (try
     (let [jwt (signed-jwt compact)
           ok? (.verify jwt (verifier (jwk/parse key)))]
       (when-not ok?
         (throw (jose-ex :invalid-signature "Invalid JWT signature" nil {})))
       (validated-claims (.getJWTClaimsSet jwt) opts))
     (catch JOSEException e
       (throw (jose-ex :invalid-signature "Invalid JWT signature" e {})))
     (catch ParseException e
       (throw (jose-ex :parse-failure "Failed to parse JWT claims" e {}))))))

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
   (validate-options! verify-options opts)
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
   (validate-options! verify-options opts)
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
