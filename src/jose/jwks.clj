(ns jose.jwks
  (:require [clojure.string :as str]
            [jose.jwk :as jwk])
  (:import (com.nimbusds.jose Algorithm KeySourceException RemoteKeySourceException)
           (com.nimbusds.jose.jwk Curve JWK JWKMatcher JWKMatcher$Builder
                                  JWKSelector KeyOperation KeyType KeyUse)
           (com.nimbusds.jose.jwk.source ImmutableJWKSet JWKSource JWKSourceBuilder)
           (com.nimbusds.jose.proc SimpleSecurityContext)
           (com.nimbusds.jose.util Base64URL DefaultResourceRetriever)
           (com.nimbusds.jose.util.events EventListener)
           (com.nimbusds.jose.util.health HealthReportListener)
           (java.net MalformedURLException URI URISyntaxException URL)
           (java.util Set)))

(set! *warn-on-reflection* true)

(def ^:private remote-options
  #{:cache? :cache-forever? :cache-ttl-ms :cache-refresh-ms
    :connect-timeout-ms :read-timeout-ms
    :refresh-ahead? :refresh-ahead-ms :refresh-ahead-scheduled?
    :rate-limit? :rate-limit-ms :retry? :failover
    :outage-tolerant? :outage-ttl-ms :outage-forever?
    :cache-event-listener :refresh-ahead-event-listener
    :rate-limit-event-listener :retry-event-listener
    :outage-event-listener :health-report-listener})

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

(defn- source
  ^JWKSource [source-value]
  (cond
    (instance? Source source-value) (:jwk-source source-value)
    (instance? JWKSource source-value) source-value
    :else (invalid-option! :source)))

(defn- event-listener
  ^EventListener [value option]
  (cond
    (nil? value) nil
    (instance? EventListener value) value
    (ifn? value) (reify EventListener
                   (notify [_ event]
                     (value event)))
    :else (invalid-option! option)))

(defn- health-report-listener
  ^HealthReportListener [value]
  (cond
    (nil? value) nil
    (instance? HealthReportListener value) value
    (ifn? value) (reify HealthReportListener
                   (notify [_ report]
                     (value report)))
    :else (invalid-option! :health-report-listener)))

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
  (let [cache-listener (event-listener (:cache-event-listener opts)
                                       :cache-event-listener)
        refresh-listener (event-listener (:refresh-ahead-event-listener opts)
                                         :refresh-ahead-event-listener)
        rate-listener (event-listener (:rate-limit-event-listener opts)
                                      :rate-limit-event-listener)
        retry-listener (event-listener (:retry-event-listener opts)
                                       :retry-event-listener)
        outage-listener (event-listener (:outage-event-listener opts)
                                        :outage-event-listener)]
    (cond
      (:cache-forever? opts) (.cacheForever builder)
      (or (contains? opts :cache-ttl-ms)
          (contains? opts :cache-refresh-ms)
          cache-listener)
      (let [ttl (long (:cache-ttl-ms opts 300000))
            refresh (long (:cache-refresh-ms opts 15000))]
        (if cache-listener
          (.cache builder ttl refresh cache-listener)
          (.cache builder ttl refresh)))
      (contains? opts :cache?) (.cache builder (boolean (:cache? opts))))
    (cond
      (contains? opts :refresh-ahead-ms)
      (let [ahead (long (:refresh-ahead-ms opts))
            scheduled? (boolean (:refresh-ahead-scheduled? opts false))]
        (if refresh-listener
          (.refreshAheadCache builder ahead scheduled? refresh-listener)
          (.refreshAheadCache builder ahead scheduled?)))
      (contains? opts :refresh-ahead?)
      (.refreshAheadCache builder (boolean (:refresh-ahead? opts)))
      (false? (:cache? opts))
      (.refreshAheadCache builder false))
    (cond
      (contains? opts :rate-limit-ms)
      (let [interval (long (:rate-limit-ms opts))]
        (if rate-listener
          (.rateLimited builder interval rate-listener)
          (.rateLimited builder interval)))
      (contains? opts :rate-limit?)
      (.rateLimited builder (boolean (:rate-limit? opts)))
      (false? (:cache? opts))
      (.rateLimited builder false))
    (cond
      retry-listener (.retrying builder retry-listener)
      (contains? opts :retry?) (.retrying builder (boolean (:retry? opts))))
    (cond
      (:outage-forever? opts) (.outageTolerantForever builder)
      (contains? opts :outage-ttl-ms)
      (let [ttl (long (:outage-ttl-ms opts))]
        (if outage-listener
          (.outageTolerant builder ttl outage-listener)
          (.outageTolerant builder ttl)))
      (contains? opts :outage-tolerant?)
      (.outageTolerant builder (boolean (:outage-tolerant? opts))))
    (when-let [listener (health-report-listener (:health-report-listener opts))]
      (.healthReporting builder listener))
    (when-let [failover (:failover opts)]
      (.failover builder (source failover))))
  builder)

(defn remote-source
  "Returns an opaque remote JWKS source.

  Without options, Nimbus defaults are used. Options configure caching,
  refresh-ahead, retry, failover, outage tolerance, rate limiting, and event
  or health listeners."
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
