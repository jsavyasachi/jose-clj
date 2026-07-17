(ns jose.jwks
  (:require [clojure.string :as str]
            [jose.jwk :as jwk])
  (:import (com.nimbusds.jose Algorithm KeySourceException RemoteKeySourceException)
           (com.nimbusds.jose.jwk Curve JWK JWKMatcher JWKMatcher$Builder
                                  JWKSelector KeyOperation KeyType KeyUse)
           (com.nimbusds.jose.jwk.source ImmutableJWKSet JWKSource JWKSourceBuilder)
           (com.nimbusds.jose.proc SimpleSecurityContext)
           (com.nimbusds.jose.util Base64URL DefaultResourceRetriever)
           (java.net MalformedURLException URI URISyntaxException URL)
           (java.util Set)))

(set! *warn-on-reflection* true)

(def ^:private remote-options
  #{:cache-ttl-ms :cache-refresh-ms :connect-timeout-ms :read-timeout-ms :rate-limit-ms})

(def ^:private get-options
  #{:kid :kty :use :alg :key-ops :curves :key-size :key-sizes
    :min-key-size :max-key-size :private? :x5t :x5t#S256})

(def ^:private curves
  {:p-256 Curve/P_256
   :p-384 Curve/P_384
   :p-521 Curve/P_521
   :secp256k1 Curve/SECP256K1
   :ed25519 Curve/Ed25519
   :x25519 Curve/X25519})

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

(defrecord Source [^JWKSource jwk-source])

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

(defn- url
  ^URL [s]
  (try
    (-> (URI. (str s))
        (.toURL))
    (catch URISyntaxException e
      (throw (jose-ex :invalid-url "Invalid JWKS URL" e {:url s})))
    (catch MalformedURLException e
      (throw (jose-ex :invalid-url "Invalid JWKS URL" e {:url s})))
    (catch IllegalArgumentException e
      (throw (jose-ex :invalid-url "Invalid JWKS URL" e {:url s})))))

(defn- key-type
  ^KeyType [kty]
  (case kty
    nil nil
    :rsa KeyType/RSA
    :ec KeyType/EC
    :okp KeyType/OKP
    :oct KeyType/OCT
    (invalid-option! :kty)))

(defn- key-use
  ^KeyUse [use]
  (case use
    nil nil
    :sig KeyUse/SIGNATURE
    :enc KeyUse/ENCRYPTION
    (invalid-option! :use)))

(defn- algorithm
  ^Algorithm [alg]
  (cond
    (nil? alg) nil
    (instance? Algorithm alg) alg
    (keyword? alg) (Algorithm/parse ^String (get alg-names alg (str/upper-case (name alg))))
    (string? alg) (Algorithm/parse ^String alg)
    :else (invalid-option! :alg)))

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

(defn- curve
  ^Curve [value]
  (cond
    (instance? Curve value) value
    (keyword? value) (or (get curves value) (invalid-option! :curves))
    (string? value) (Curve/parse value)
    :else (invalid-option! :curves)))

(defn matcher
  "Builds a Nimbus JWKMatcher from matcher options."
  ^JWKMatcher [opts]
  (validate-options! get-options opts)
  (let [builder (JWKMatcher$Builder.)]
    (when-let [kid (:kid opts)]
      (.keyID builder (str kid)))
    (when-let [kty (key-type (:kty opts))]
      (.keyType builder kty))
    (when-let [use (key-use (:use opts))]
      (.keyUse builder use))
    (when-let [alg (algorithm (:alg opts))]
      (.algorithm builder alg))
    (when-let [operations (:key-ops opts)]
      (let [^Set operations (set (map key-operation operations))]
        (.keyOperations builder operations)))
    (when-let [curve-values (:curves opts)]
      (let [^Set curve-values (set (map curve curve-values))]
        (.curves builder curve-values)))
    (when-let [size (:key-size opts)]
      (.keySize builder (int size)))
    (when-let [sizes (:key-sizes opts)]
      (let [^Set sizes (set (map #(Integer/valueOf (int %)) sizes))]
        (.keySizes builder sizes)))
    (when-let [size (:min-key-size opts)]
      (.minKeySize builder (int size)))
    (when-let [size (:max-key-size opts)]
      (.maxKeySize builder (int size)))
    (when (contains? opts :private?)
      (if (:private? opts)
        (.privateOnly builder true)
        (.publicOnly builder true)))
    (when-let [thumbprint (:x5t#S256 opts)]
      (.x509CertSHA256Thumbprint builder (Base64URL. (str thumbprint))))
    (.build builder)))

(defn- selector
  ^JWKSelector [opts]
  (JWKSelector. (matcher opts)))

(defn- matches-x5t?
  [^JWK key x5t]
  (or (nil? x5t)
      (= (str x5t) (some-> key .getX509CertThumbprint str))))

(defn- resource-retriever
  ^DefaultResourceRetriever [opts]
  (when (or (contains? opts :connect-timeout-ms)
            (contains? opts :read-timeout-ms))
    (DefaultResourceRetriever.
     (int (:connect-timeout-ms opts 5000))
     (int (:read-timeout-ms opts 5000)))))

(defn- builder
  ^JWKSourceBuilder [jwks-url opts]
  (if-let [retriever (resource-retriever opts)]
    (JWKSourceBuilder/create (url jwks-url) retriever)
    (JWKSourceBuilder/create (url jwks-url))))

(defn- configure-builder!
  ^JWKSourceBuilder [^JWKSourceBuilder builder opts]
  (when (or (contains? opts :cache-ttl-ms)
            (contains? opts :cache-refresh-ms))
    (.cache builder
            (long (:cache-ttl-ms opts 300000))
            (long (:cache-refresh-ms opts 15000))))
  (when-let [rate-limit-ms (:rate-limit-ms opts)]
    (.rateLimited builder (long rate-limit-ms)))
  builder)

(defn remote-source
  "Returns an opaque remote JWKS source.

  Without options, Nimbus defaults are used; its default URL builder already
  caches keys. Pass timeout, cache, or rate-limit options to override those
  builder settings. Force refresh is omitted because Nimbus exposes no public
  force-refresh method on the verified caching source API."
  (^Source [jwks-url]
   (remote-source jwks-url {}))
  (^Source [jwks-url opts]
   (validate-options! remote-options opts)
   (->Source (.build (configure-builder! (builder jwks-url opts) opts)))))

(defn local-source
  "Returns an opaque in-memory JWKS source."
  ^Source [jwk-set-or-vector]
  (->Source (ImmutableJWKSet. (if (sequential? jwk-set-or-vector)
                                (jwk/jwk-set jwk-set-or-vector)
                                (jwk/parse-set jwk-set-or-vector)))))

(defn- source
  ^JWKSource [source-value]
  (cond
    (instance? Source source-value) (:jwk-source source-value)
    (instance? JWKSource source-value) source-value
    :else (invalid-option! :source)))

(defn get-keys
  "Returns Nimbus JWKs matching the supplied JWK matcher options."
  [source-value opts]
  (try
    (->> (.get (source source-value)
               (selector opts)
               (SimpleSecurityContext.))
         (filter #(matches-x5t? % (:x5t opts)))
         vec)
    (catch RemoteKeySourceException e
      (throw (jose-ex :key-source-failure "Failed to retrieve remote JWKS" e {})))
    (catch KeySourceException e
      (throw (jose-ex :key-source-failure "Failed to retrieve JWKS" e {})))))

(defn find-key
  "Returns the first key with kid, or nil."
  ^JWK [source-value kid]
  (first (get-keys source-value {:kid kid})))
