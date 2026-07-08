(ns jose.jwks
  (:require [clojure.string :as str]
            [jose.jwk :as jwk])
  (:import (com.nimbusds.jose Algorithm KeySourceException RemoteKeySourceException)
           (com.nimbusds.jose.jwk JWK JWKMatcher$Builder JWKSelector KeyType KeyUse)
           (com.nimbusds.jose.jwk.source ImmutableJWKSet JWKSource JWKSourceBuilder)
           (com.nimbusds.jose.proc SimpleSecurityContext)
           (com.nimbusds.jose.util DefaultResourceRetriever)
           (java.net MalformedURLException URI URISyntaxException URL)))

(set! *warn-on-reflection* true)

(def ^:private remote-options
  #{:cache-ttl-ms :cache-refresh-ms :connect-timeout-ms :read-timeout-ms :rate-limit-ms})

(def ^:private get-options #{:kid :kty :use :alg})

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

(defn- selector
  ^JWKSelector [opts]
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
    (JWKSelector. (.build builder))))

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
  "Returns a vector of Nimbus JWKs matching optional :kid, :kty, :use, and :alg."
  [source-value opts]
  (try
    (vec (.get (source source-value)
               (selector opts)
               (SimpleSecurityContext.)))
    (catch RemoteKeySourceException e
      (throw (jose-ex :key-source-failure "Failed to retrieve remote JWKS" e {})))
    (catch KeySourceException e
      (throw (jose-ex :key-source-failure "Failed to retrieve JWKS" e {})))))

(defn find-key
  "Returns the first key with kid, or nil."
  ^JWK [source-value kid]
  (first (get-keys source-value {:kid kid})))
