(ns jose.jwk
  (:require [clojure.string :as str])
  (:import (com.nimbusds.jose Algorithm JOSEException)
           (com.nimbusds.jose.jwk Curve ECKey$Builder JWK JWKMatcher JWKSet
                                  KeyOperation KeyRevocation KeyRevocation$Reason
                                  KeyType KeyUse KeyConverter PasswordLookup
                                  OctetKeyPair
                                  OctetKeyPair$Builder OctetSequenceKey$Builder
                                  RSAKey$Builder)
           (com.nimbusds.jose.jwk.gen ECKeyGenerator JWKGenerator
                                       OctetKeyPairGenerator
                                       OctetSequenceKeyGenerator
                                       RSAKeyGenerator)
           (com.nimbusds.jose.util Base64 Base64URL)
           (java.io File IOException InputStream)
           (java.net URI)
           (java.security KeyFactory KeyStore KeyStoreException PrivateKey Provider SecureRandom)
           (java.security.cert X509Certificate)
           (java.security.spec PKCS8EncodedKeySpec X509EncodedKeySpec)
           (java.text ParseException)
           (java.time Instant)
           (java.util ArrayList Date HashSet List Map Set)))

(set! *warn-on-reflection* true)

(def ^:private common-options
  #{:kid :use :alg :key-ops :x5c :x5u :x5t :x5t#S256
    :iat :nbf :exp :revoked})
(def ^:private type-options
  {:rsa (conj common-options :size :key-store :provider :secure-random)
   :ec (conj common-options :curve :key-store :provider :secure-random)
   :okp (conj common-options :curve :key-store :provider :secure-random)
   :oct (conj common-options :size :key-store :provider :secure-random)})

(def ^:private curves
  {:p-256 Curve/P_256
   :p-384 Curve/P_384
   :p-521 Curve/P_521
   :secp256k1 Curve/SECP256K1
   :ed25519 Curve/Ed25519
   :x25519 Curve/X25519})

;; RFC 8410 SubjectPublicKeyInfo prefixes for id-Ed25519 (1.3.101.112) and
;; id-X25519 (1.3.101.110). They encode SEQUENCE/algorithm/unused-bits and
;; leave the final 32-byte public key to be appended below.
(def ^:private okp-ed25519-spki-prefix
  (byte-array [48 42 48 5 6 3 43 101 112 3 33 0]))
(def ^:private okp-x25519-spki-prefix
  (byte-array [48 42 48 5 6 3 43 101 110 3 33 0]))
;; RFC 8410 PKCS#8 PrivateKeyInfo prefixes for the same OIDs. They encode the
;; version, algorithm identifier, and an OCTET STRING containing a 32-byte seed.
(def ^:private okp-ed25519-pkcs8-prefix
  (byte-array [48 46 2 1 0 48 5 6 3 43 101 112 4 34 4 32]))
(def ^:private okp-x25519-pkcs8-prefix
  (byte-array [48 46 2 1 0 48 5 6 3 43 101 110 4 34 4 32]))

(def ^:private alg-names
  {:rs256 "RS256"
   :rs384 "RS384"
   :rs512 "RS512"
   :ps256 "PS256"
   :ps384 "PS384"
   :ps512 "PS512"
   :es256 "ES256"
   :es256k "ES256K"
   :es384 "ES384"
   :es512 "ES512"
   :eddsa "EdDSA"
   :a128kw "A128KW"
   :a192kw "A192KW"
   :a256kw "A256KW"
   :dir "dir"})

(defn- jose-ex
  [error message cause data]
  (ex-info message (assoc data :jose/error error) cause))

(defn- wrap-parse
  [f]
  (try
    (f)
    (catch ParseException e
      (throw (jose-ex :parse-failure "Failed to parse JWK" e {})))
    (catch RuntimeException e
      (throw (jose-ex :parse-failure "Failed to parse JWK" e {})))))

(defn- wrap-jose
  [error message f]
  (try
    (f)
    (catch JOSEException e
      (throw (jose-ex error message e {})))))

(defn- invalid-option!
  [option]
  (throw (ex-info (str "Invalid option " option)
                  {:jose/error :invalid-option
                   :option option})))

(defn- validate-options!
  [kind opts]
  (when-not (contains? type-options kind)
    (throw (ex-info (str "Invalid JWK type " kind)
                    {:jose/error :invalid-option
                     :option kind})))
  (let [allowed (get type-options kind)]
    (doseq [option (keys opts)]
      (when-not (contains? allowed option)
        (invalid-option! option)))
    (when (and (= kind :oct) (contains? opts :provider))
      (invalid-option! :provider))
    (when (and (= kind :okp)
               (or (contains? opts :provider)
                   (contains? opts :key-store)))
      (invalid-option! (if (contains? opts :provider) :provider :key-store)))
    (when (and (= kind :okp)
               (contains? opts :secure-random)
               (= "x25519"
                  (some-> (:curve opts) name str/lower-case)))
      (invalid-option! :secure-random))))

(defn- parse-key-use
  [use]
  (case use
    nil nil
    :sig KeyUse/SIGNATURE
    :enc KeyUse/ENCRYPTION
    (invalid-option! :use)))

(defn- parse-algorithm
  [alg]
  (cond
    (nil? alg) nil
    (instance? Algorithm alg) alg
    (keyword? alg) (Algorithm/parse (get alg-names alg (str/upper-case (name alg))))
    (string? alg) (Algorithm/parse alg)
    :else (invalid-option! :alg)))

(defn- curve
  [c]
  (cond
    (nil? c) nil
    (instance? Curve c) c
    (keyword? c) (or (get curves c) (invalid-option! :curve))
    (string? c) (Curve/parse c)
    :else (invalid-option! :curve)))

(defn- key-operation
  ^KeyOperation [operation]
  (case operation
    :sign KeyOperation/SIGN
    :verify KeyOperation/VERIFY
    :encrypt KeyOperation/ENCRYPT
    :decrypt KeyOperation/DECRYPT
    :wrap-key KeyOperation/WRAP_KEY
    :unwrap-key KeyOperation/UNWRAP_KEY
    :derive-key KeyOperation/DERIVE_KEY
    :derive-bits KeyOperation/DERIVE_BITS
    (invalid-option! :key-ops)))

(defn- java-set
  ^Set [xs]
  (let [result (HashSet.)]
    (doseq [x xs]
      (.add result x))
    result))

(defn- date
  ^Date [option value]
  (cond
    (nil? value) nil
    (instance? Date value) value
    (instance? Instant value) (Date/from ^Instant value)
    (integer? value) (Date. (* 1000 (long value)))
    :else (invalid-option! option)))

(defn- key-revocation
  ^KeyRevocation [value]
  (cond
    (instance? KeyRevocation value) value
    (map? value)
    (let [reason (:reason value)
          reason (cond
                   (instance? KeyRevocation$Reason reason) reason
                   (keyword? reason) (KeyRevocation$Reason/parse (name reason))
                   (string? reason) (KeyRevocation$Reason/parse reason)
                   :else (invalid-option! :revoked))]
      (KeyRevocation. (date :revoked (:at value)) reason))
    :else (invalid-option! :revoked)))

(defn- configure-generator!
  [^JWKGenerator generator opts]
  (let [use (parse-key-use (:use opts))
        alg (parse-algorithm (:alg opts))
        kid (:kid opts)
        operations (when-let [operations (:key-ops opts)]
                     (java-set (map key-operation operations)))]
    (when use
      (.keyUse generator use))
    (when operations
      (.keyOperations generator operations))
    (when alg
      (.algorithm generator alg))
    (when (contains? opts :iat)
      (.issueTime generator (date :iat (:iat opts))))
    (when (contains? opts :nbf)
      (.notBeforeTime generator (date :nbf (:nbf opts))))
    (when (contains? opts :exp)
      (.expirationTime generator (date :exp (:exp opts))))
    (when (contains? opts :key-store)
      (.keyStore generator ^KeyStore (:key-store opts)))
    (when (contains? opts :provider)
      (.provider generator ^Provider (:provider opts)))
    (when (contains? opts :secure-random)
      (.secureRandom generator ^SecureRandom (:secure-random opts)))
    (if (contains? opts :kid)
      (.keyID generator kid)
      (.keyIDFromThumbprint generator true))
    generator))

(defn- java-list
  ^List [xs]
  (let [list (ArrayList.)]
    (doseq [x xs]
      (.add list x))
    list))

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

(defn parse
  "Parses a JWK JSON string, Clojure map, or returns a Nimbus JWK unchanged."
  ^JWK [s-or-map]
  (wrap-parse
   (fn []
     (cond
       (instance? JWK s-or-map) s-or-map
       (string? s-or-map) (JWK/parse ^String s-or-map)
       (map? s-or-map) (JWK/parse ^Map (stringify-json-value s-or-map))
       :else (throw (IllegalArgumentException. "Expected JWK, JSON string, or map"))))))

(defn certificate->jwk
  "Imports the public key and X.509 metadata from a certificate."
  ^JWK [certificate]
  (wrap-jose
   :key-import-failure
   "Failed to import X.509 certificate"
   #(JWK/parse ^X509Certificate certificate)))

(defn keystore->jwk
  "Imports a key store entry by alias. The PIN may be a string, char array, or nil."
  ^JWK [keystore alias pin]
  (let [pin (cond
              (nil? pin) nil
              (string? pin) (.toCharArray ^String pin)
              (= (class pin) (Class/forName "[C")) pin
              :else (invalid-option! :pin))]
    (try
      (JWK/load ^KeyStore keystore (str alias) ^chars pin)
      (catch KeyStoreException e
        (throw (jose-ex :key-import-failure
                        "Failed to import key store entry"
                        e
                        {:alias alias})))
      (catch JOSEException e
        (throw (jose-ex :key-import-failure
                        "Failed to import key store entry"
                        e
                        {:alias alias}))))))

(defn- jca-key-factory
  ^KeyFactory [^String algorithm]
  (try
    (KeyFactory/getInstance algorithm)
    (catch java.security.NoSuchAlgorithmException e
      (throw (jose-ex :key-import-failure
                      "JDK does not support JWK key algorithm; OKP JCA conversion requires JDK 15+"
                      e
                      {:algorithm algorithm
                       :required-jdk 15})))))

(defn to-java-keys
  "Converts one JWK or a collection of JWK inputs to Java security keys."
  [jwk-or-jwks]
  (try
    (let [jwks (mapv parse (if (coll? jwk-or-jwks) jwk-or-jwks [jwk-or-jwks]))]
      (vec (mapcat (fn [^JWK jwk]
                     (let [converted (KeyConverter/toJavaKeys ^List (java-list [jwk]))]
                       (if (seq converted)
                         converted
                         (cond
                           (= KeyType/OKP (.getKeyType jwk))
                           (let [^OctetKeyPair key (.toOctetKeyPair jwk)
                                 curve (.getName (.getCurve key))
                                 prefix (if (= "Ed25519" curve)
                                          okp-ed25519-spki-prefix
                                          okp-x25519-spki-prefix)
                                 factory (jca-key-factory curve)
                                 public-key (.generatePublic factory
                                                              (X509EncodedKeySpec.
                                                               (byte-array (concat prefix (.decode (.getX key))))))]
                             (if (.isPrivate jwk)
                               (let [private-prefix (if (= "Ed25519" curve)
                                                      okp-ed25519-pkcs8-prefix
                                                      okp-x25519-pkcs8-prefix)
                                     private-key (.generatePrivate factory
                                                                    (PKCS8EncodedKeySpec.
                                                                     (byte-array (concat private-prefix
                                                                                         (.decode (.getD key))))))]
                                 [public-key private-key])
                               [public-key]))
                           :else []))))
                   jwks)))
    (catch java.security.NoSuchAlgorithmException e
      (throw (jose-ex :key-import-failure
                      "JDK does not support JWK key algorithm; OKP JCA conversion requires JDK 15+"
                      e
                      {:algorithm (.getMessage e)
                       :required-jdk 15})))
    (catch clojure.lang.ExceptionInfo e
      (throw e))
    (catch RuntimeException e
      (throw (jose-ex :key-import-failure "Failed to convert JWK to Java key" e {})))))

(defn to-java-private-key
  "Converts one private JWK input to its private Java security key."
  ^PrivateKey [jwk]
  (or (some #(when (instance? PrivateKey %) %) (to-java-keys [jwk]))
      (throw (jose-ex :key-import-failure "JWK has no private Java key" nil {}))))

(defn keystore->jwks
  "Loads all private key entries from a key store using per-alias passwords."
  ^JWKSet [^KeyStore keystore passwords]
  (let [lookup (cond
                 (map? passwords) (fn [alias] (get passwords alias))
                 (ifn? passwords) passwords
                 :else (invalid-option! :passwords))
        password-chars (fn [password]
                         (cond
                           (nil? password) nil
                           (string? password) (.toCharArray ^String password)
                           (= (class password) (Class/forName "[C")) password
                           :else (invalid-option! :passwords)))
        password-lookup (reify PasswordLookup
                          (lookupPassword [_ alias]
                            (password-chars (lookup alias))))]
    (try
      (let [aliases (filter #(.isKeyEntry keystore ^String %)
                            (enumeration-seq (.aliases keystore)))
            loaded-entries
              (mapv (fn [alias]
                      (try
                        (JWK/load keystore alias ^chars (password-chars (lookup alias)))
                        (catch KeyStoreException e
                          (throw (jose-ex :key-import-failure
                                          "Failed to import key store entry"
                                          e
                                          {:alias alias})))
                        (catch JOSEException e
                          (throw (jose-ex :key-import-failure
                                          "Failed to import key store entry"
                                          e
                                          {:alias alias})))))
                    aliases)
              loaded (JWKSet/load keystore password-lookup)
              key-entry-count (count aliases)]
          (if (= key-entry-count (.size loaded))
            loaded
            (JWKSet. ^List (java-list loaded-entries))))
      (catch KeyStoreException e
        (throw (jose-ex :key-import-failure "Failed to import key store" e {}))))))

(defn ->map
  "Returns the complete JWK JSON representation as a Clojure map."
  [jwk]
  (let [^JWK jwk (parse jwk)]
    (keywordize-json-value (.toJSONObject jwk))))

(defn public-jwk
  "Returns a public-only JWK, or nil when the key has no public form."
  ^JWK [jwk]
  (let [^JWK jwk (parse jwk)
        public (.toPublicJWK jwk)]
    (when (some? public)
      public)))

(defn ->json
  "Returns a JWK JSON string. Pass {:private? false} for a public-only JWK."
  (^String [jwk]
   (->json jwk {:private? true}))
  (^String [jwk opts]
   (doseq [option (keys opts)]
     (when-not (= :private? option)
       (invalid-option! option)))
   (let [^JWK jwk (if (:private? opts true)
                    (parse jwk)
                    (public-jwk jwk))]
     (when jwk
       (.toJSONString jwk)))))

(defn thumbprint
  "Returns the RFC 7638 SHA-256 JWK thumbprint."
  [jwk]
  (wrap-jose
   :thumbprint-failure
   "Failed to compute JWK thumbprint"
   (fn []
     (let [^JWK jwk (parse jwk)]
       (str (.computeThumbprint jwk))))))

(defn thumbprint-uri
  "Returns the RFC 9278 JWK thumbprint URI for the SHA-256 thumbprint."
  [jwk]
  (wrap-jose
   :thumbprint-failure
   "Failed to compute JWK thumbprint URI"
   (fn []
     (let [^JWK jwk (parse jwk)]
       (str (.computeThumbprintURI jwk))))))

(defn key-type
  [jwk]
  (let [^JWK jwk (parse jwk)
        key-type (.getKeyType jwk)]
    (cond
      (= KeyType/RSA key-type) :rsa
      (= KeyType/EC key-type) :ec
      (= KeyType/OKP key-type) :okp
      (= KeyType/OCT key-type) :oct
      :else (keyword (str/lower-case (str key-type))))))

(defn key-id
  [jwk]
  (let [^JWK jwk (parse jwk)]
    (.getKeyID jwk)))

(defn key-use
  "Returns the JWK key use as :sig, :enc, or nil."
  [jwk]
  (let [^JWK jwk (parse jwk)
        use (.getKeyUse jwk)]
    (when use
      (keyword (str/lower-case (.getValue ^KeyUse use))))))

(defn key-operations
  "Returns the JWK key operations as a set of keywords, or nil."
  [jwk]
  (let [^JWK jwk (parse jwk)
        operations (.getKeyOperations jwk)]
    (when operations
      (set (map #(keyword (str/lower-case (.identifier ^KeyOperation %)))
                operations)))))

(defn algorithm
  "Returns the JWK algorithm as a keyword, or nil."
  [jwk]
  (let [^JWK jwk (parse jwk)
        alg (.getAlgorithm jwk)]
    (when alg
      (keyword (str/lower-case (str alg))))))

(defn- instant
  ^Instant [^Date value]
  (when value
    (Instant/ofEpochMilli (.getTime value))))

(defn issue-time
  "Returns the JWK issue time as an Instant, or nil."
  [jwk]
  (instant (.getIssueTime ^JWK (parse jwk))))

(defn not-before-time
  "Returns the JWK not-before time as an Instant, or nil."
  [jwk]
  (instant (.getNotBeforeTime ^JWK (parse jwk))))

(defn expiration-time
  "Returns the JWK expiration time as an Instant, or nil."
  [jwk]
  (instant (.getExpirationTime ^JWK (parse jwk))))

(defn x509-cert-url
  "Returns the JWK X.509 certificate URL as a string, or nil."
  [jwk]
  (some-> (.getX509CertURL ^JWK (parse jwk)) str))

(defn x509-cert-chain
  "Returns the JWK X.509 certificate chain as Base64 strings, or nil."
  [jwk]
  (some->> (.getX509CertChain ^JWK (parse jwk)) (mapv str)))

(defn x509-certificates
  "Returns the JWK X.509 certificate chain as X509Certificate objects, or nil."
  [jwk]
  (let [^JWK jwk (parse jwk)]
    (when (.getX509CertChain jwk)
      (try
        (vec (.getParsedX509CertChain jwk))
        (catch RuntimeException e
          (throw (jose-ex :parse-failure
                          "Failed to parse JWK X.509 certificate chain"
                          e
                          {})))))))

(defn x509-cert-thumbprint
  "Returns the JWK X.509 certificate SHA-1 thumbprint as a string, or nil."
  [jwk]
  (some-> (.getX509CertThumbprint ^JWK (parse jwk)) str))

(defn x509-cert-sha256-thumbprint
  "Returns the JWK X.509 certificate SHA-256 thumbprint as a string, or nil."
  [jwk]
  (some-> (.getX509CertSHA256Thumbprint ^JWK (parse jwk)) str))

(defn private?
  [jwk]
  (let [^JWK jwk (parse jwk)]
    (.isPrivate jwk)))

(defn- set-rsa-x509!
  [^RSAKey$Builder builder opts]
  (when (contains? opts :x5u)
    (.x509CertURL builder (some-> (:x5u opts) str URI.)))
  (when (contains? opts :x5t)
    (.x509CertThumbprint builder (some-> (:x5t opts) str Base64URL.)))
  (when (contains? opts :x5t#S256)
    (.x509CertSHA256Thumbprint builder (some-> (:x5t#S256 opts) str Base64URL.)))
  (when (contains? opts :x5c)
    (.x509CertChain builder (java-list (map #(Base64. (str %)) (:x5c opts)))))
  (when (contains? opts :revoked)
    (.keyRevocation builder (key-revocation (:revoked opts))))
  (.build builder))

(defn- set-ec-x509!
  [^ECKey$Builder builder opts]
  (when (contains? opts :x5u)
    (.x509CertURL builder (some-> (:x5u opts) str URI.)))
  (when (contains? opts :x5t)
    (.x509CertThumbprint builder (some-> (:x5t opts) str Base64URL.)))
  (when (contains? opts :x5t#S256)
    (.x509CertSHA256Thumbprint builder (some-> (:x5t#S256 opts) str Base64URL.)))
  (when (contains? opts :x5c)
    (.x509CertChain builder (java-list (map #(Base64. (str %)) (:x5c opts)))))
  (when (contains? opts :revoked)
    (.keyRevocation builder (key-revocation (:revoked opts))))
  (.build builder))

(defn- set-oct-x509!
  [^OctetSequenceKey$Builder builder opts]
  (when (contains? opts :x5u)
    (.x509CertURL builder (some-> (:x5u opts) str URI.)))
  (when (contains? opts :x5t)
    (.x509CertThumbprint builder (some-> (:x5t opts) str Base64URL.)))
  (when (contains? opts :x5t#S256)
    (.x509CertSHA256Thumbprint builder (some-> (:x5t#S256 opts) str Base64URL.)))
  (when (contains? opts :x5c)
    (.x509CertChain builder (java-list (map #(Base64. (str %)) (:x5c opts)))))
  (when (contains? opts :revoked)
    (.keyRevocation builder (key-revocation (:revoked opts))))
  (.build builder))

(defn- set-okp-x509!
  [^OctetKeyPair$Builder builder opts]
  (when (contains? opts :x5u)
    (.x509CertURL builder (some-> (:x5u opts) str URI.)))
  (when (contains? opts :x5t)
    (.x509CertThumbprint builder (some-> (:x5t opts) str Base64URL.)))
  (when (contains? opts :x5t#S256)
    (.x509CertSHA256Thumbprint builder (some-> (:x5t#S256 opts) str Base64URL.)))
  (when (contains? opts :x5c)
    (.x509CertChain builder (java-list (map #(Base64. (str %)) (:x5c opts)))))
  (when (contains? opts :revoked)
    (.keyRevocation builder (key-revocation (:revoked opts))))
  (.build builder))

(defn- configure-metadata
  ^JWK [^JWK generated opts]
  (if-not (some #(contains? opts %) [:x5c :x5u :x5t :x5t#S256 :revoked])
    generated
    (case (key-type generated)
      :rsa (set-rsa-x509! (RSAKey$Builder. (.toRSAKey generated)) opts)
      :ec (set-ec-x509! (ECKey$Builder. (.toECKey generated)) opts)
      :oct (set-oct-x509! (OctetSequenceKey$Builder. (.toOctetSequenceKey generated)) opts)
      :okp (set-okp-x509! (OctetKeyPair$Builder. (.toOctetKeyPair generated)) opts))))

(defn generate
  "Generates a Nimbus JWK. Kind is one of :rsa, :ec, :okp, or :oct."
  (^JWK [kind]
   (generate kind {}))
  (^JWK [kind opts]
   (validate-options! kind opts)
   (wrap-jose
    :generation-failure
    "Failed to generate JWK"
    (fn []
      (case kind
        :rsa (let [^RSAKeyGenerator generator
                   (RSAKeyGenerator. (long (:size opts 2048)))]
               (configure-generator! generator opts)
               (configure-metadata (.generate generator) opts))
        :ec (let [^ECKeyGenerator generator
                  (ECKeyGenerator. (curve (:curve opts :p-256)))]
              (configure-generator! generator opts)
              (configure-metadata (.generate generator) opts))
        :okp (try
               (let [^OctetKeyPairGenerator generator
                     (OctetKeyPairGenerator. (curve (:curve opts :ed25519)))]
                 (configure-generator! generator opts)
                 (configure-metadata (.generate generator) opts))
               (catch NoClassDefFoundError e
                 (throw (jose-ex :missing-optional-dep
                                 "Missing optional Tink dependency"
                                 e
                                 {:dep "com.google.crypto.tink/tink"}))))
        :oct (let [^OctetSequenceKeyGenerator generator
                   (OctetSequenceKeyGenerator. (long (:size opts 256)))]
               (configure-generator! generator opts)
               (configure-metadata (.generate generator) opts)))))))

(defn jwk-set
  (^JWKSet [jwks]
   (jwk-set jwks {}))
  (^JWKSet [jwks members]
   (JWKSet. (java-list (map parse jwks))
            (stringify-json-value members))))

(defn parse-set
  "Parses a JWKS JSON string, Clojure map, or returns a Nimbus JWKSet unchanged."
  ^JWKSet [s-or-map]
  (wrap-parse
   (fn []
     (cond
       (instance? JWKSet s-or-map) s-or-map
       (string? s-or-map) (JWKSet/parse ^String s-or-map)
       (map? s-or-map) (JWKSet/parse ^Map (stringify-json-value s-or-map))
       :else (throw (IllegalArgumentException. "Expected JWKSet, JSON string, or map"))))))

(defn load-set
  "Loads a JWK set from a file, input stream, JSON string, or Nimbus JWKSet."
  ^JWKSet [source]
  (try
    (cond
      (instance? File source) (JWKSet/load ^File source)
      (instance? InputStream source) (JWKSet/load ^InputStream source)
      :else (parse-set source))
    (catch IOException e
      (throw (jose-ex :parse-failure "Failed to load JWK set" e {})))
    (catch ParseException e
      (throw (jose-ex :parse-failure "Failed to load JWK set" e {})))))

(defn set->maps
  [jwks]
  (let [^JWKSet jwks (parse-set jwks)]
    (mapv ->map (.getKeys jwks))))

(defn find-key
  ^JWK [jwks kid]
  (let [^JWKSet jwks (parse-set jwks)]
    (.getKeyByKeyId jwks kid)))

(defn set-contains?
  "Returns true when the set contains a JWK with the same thumbprint."
  [jwks candidate]
  (wrap-jose
   :thumbprint-failure
   "Failed to compare JWK thumbprints"
   (fn []
     (let [^JWKSet jwks (parse-set jwks)]
       (.containsJWK jwks (parse candidate))))))

(defn filter-set
  "Returns the JWKs matching a Nimbus JWKMatcher."
  ^JWKSet [jwks matcher]
  (let [^JWKSet jwks (parse-set jwks)]
    (.filter jwks ^JWKMatcher matcher)))

(defn set-members
  "Returns top-level JWK set members other than keys."
  [jwks]
  (let [^JWKSet jwks (parse-set jwks)]
    (keywordize-json-value (.getAdditionalMembers jwks))))

(defn public-jwk-set
  "Returns a public JWK set with all private and symmetric material removed."
  ^JWKSet [jwks]
  (let [^JWKSet jwks (parse-set jwks)]
    (.toPublicJWKSet jwks)))

(defn set->json
  (^String [jwks]
   (set->json jwks {:private? false}))
  (^String [jwks opts]
   (doseq [option (keys opts)]
     (when-not (= :private? option)
       (invalid-option! option)))
   (let [^JWKSet jwks (if (:private? opts)
                        (parse-set jwks)
                        (public-jwk-set jwks))]
     (.toString jwks (not (:private? opts))))))
