(ns jose.mint
  (:require [jose.jwk :as jwk]
            [jose.jws :as jws]
            [jose.jwks :as jwks])
  (:import (com.nimbusds.jose JOSEException JWSAlgorithm JWSHeader JWSHeader$Builder JWSObject
                              KeySourceException Payload)
           (com.nimbusds.jose.crypto.factories DefaultJWSSignerFactory)
           (com.nimbusds.jose.jwk JWKSet)
           (com.nimbusds.jose.jwk.source ImmutableJWKSet JWKSource)
           (com.nimbusds.jose.mint ConfigurableJWSMinter DefaultJWSMinter)
           (com.nimbusds.jose.produce JWSSignerFactory)
           (jose.jwks Source)))

(set! *warn-on-reflection* true)

(defrecord Minter [^ConfigurableJWSMinter native-minter source
                   ^JWKSource jwk-source
                   ^JWSSignerFactory signer-factory])

(def ^:private minter-options #{:signer-factory})
(def ^:private mint-options #{:alg :kid :typ :cty :crit :headers})

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

(defn- native-source
  ^JWKSource [source-value]
  (cond
    (instance? Source source-value) (:jwk-source source-value)
    (instance? JWKSource source-value) source-value
    (instance? JWKSet source-value) (ImmutableJWKSet. ^JWKSet source-value)
    (sequential? source-value) (ImmutableJWKSet. (jwk/jwk-set source-value))
    :else (invalid-option! :source)))

(defn- payload
  ^Payload [value]
  (cond
    (string? value) (Payload. ^String value)
    (bytes? value) (Payload. ^bytes value)
    :else (invalid-option! :payload)))

(defn- header
  ^JWSHeader [opts]
  (when-not (contains? opts :alg)
    (invalid-option! :alg))
  (let [^JWSAlgorithm algorithm (jws/algorithm (:alg opts))
        ^JWSHeader$Builder builder (JWSHeader$Builder. algorithm)
        headers (merge (:headers opts) (select-keys opts [:typ :cty :crit]))]
    (doseq [[k v] headers]
      (jws/apply-header! builder k v))
    (when-let [kid (:kid opts)]
      (.keyID builder (str kid)))
    (.build builder)))

(defn minter
  "Creates an opaque Nimbus JWS minter backed by a JWKS source."
  ([source-value]
   (minter source-value {}))
  ([source-value opts]
   (validate-options! minter-options opts)
   (let [^JWKSource source (native-source source-value)
         ^JWSSignerFactory factory (:signer-factory opts (DefaultJWSSignerFactory.))]
     (when-not (instance? JWSSignerFactory factory)
       (invalid-option! :signer-factory))
     (let [^ConfigurableJWSMinter native (DefaultJWSMinter.)]
       (.setJWKSource native source)
       (.setJWSSignerFactory native factory)
       (->Minter native source-value source factory)))))

(defn mint
  "Mints a compact JWS after Nimbus selects a signing key from the source."
  ([minter-value payload-value]
   (mint minter-value payload-value {}))
  ([^Minter minter-value payload-value opts]
   (validate-options! mint-options opts)
   (try
     (let [^DefaultJWSMinter native (:native-minter minter-value)
           ^JWSObject object (.mint native (header opts) (payload payload-value) nil)]
       (.serialize object))
     (catch KeySourceException e
       (throw (jose-ex :key-source-failure "Failed to retrieve JWKS" e {})))
     (catch JOSEException e
       ;; DefaultJWSMinter is the source of this message; pin it in the tests.
       (if (= "No JWKs found for signing" (.getMessage e))
         (throw (jose-ex :key-not-found "No matching JWK found" e {}))
         (throw (jose-ex :sign-failure "Failed to mint JWS" e {})))))))

(defn source
  "Returns the source value configured on a minter."
  [^Minter minter-value]
  (:source minter-value))

(defn jwk-source
  "Returns the underlying Nimbus JWKSource configured on a minter."
  ^JWKSource [^Minter minter-value]
  (:jwk-source minter-value))

(defn signer-factory
  "Returns the Nimbus signer factory configured on a minter."
  ^JWSSignerFactory [^Minter minter-value]
  (:signer-factory minter-value))
