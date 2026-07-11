(ns jose.pem
  (:require [clojure.string :as str]
            [jose.jwk :as jwk])
  (:import (com.nimbusds.jose JOSEException)
           (com.nimbusds.jose.jwk ECKey JWK KeyType OctetKeyPair RSAKey)
           (java.security PrivateKey PublicKey)
           (java.util Base64)))

(set! *warn-on-reflection* true)

(def ^:private pem-options #{:private?})

(defn- jose-ex
  [error message cause data]
  (ex-info message (assoc data :jose/error error) cause))

(defn- invalid-option!
  [option message cause]
  (throw (jose-ex :invalid-option message cause {:option option})))

(defn- validate-options!
  [opts]
  (doseq [option (keys opts)]
    (when-not (contains? pem-options option)
      (invalid-option! option (str "Invalid option " option) nil))))

(defn- missing-bcpkix!
  [cause]
  (throw (jose-ex :missing-optional-dep
                  "Missing optional BouncyCastle PKIX dependency"
                  cause
                  {:dep "org.bouncycastle/bcpkix-jdk18on"})))

(defn- parse-failure!
  [message cause]
  (throw (jose-ex :parse-failure message cause {})))

(defn- certificate-pem?
  [pem]
  (str/includes? pem "-----BEGIN CERTIFICATE-----"))

(defn- parse-objects
  ^JWK [^String pem]
  (try
    (JWK/parseFromPEMEncodedObjects pem)
    (catch NoClassDefFoundError e
      (missing-bcpkix! e))
    (catch ClassNotFoundException e
      (missing-bcpkix! e))))

(defn- parse-certificate
  ^JWK [^String pem]
  (try
    (JWK/parseFromPEMEncodedX509Cert pem)
    (catch NoClassDefFoundError e
      (missing-bcpkix! e))
    (catch ClassNotFoundException e
      (missing-bcpkix! e))))

(defn pem->jwk
  "Parses PEM public keys, private keys, and X.509 certificates into a JWK map."
  [pem]
  (let [pem (str pem)]
    (try
      (jwk/->map (parse-objects pem))
      (catch JOSEException e
        (if (certificate-pem? pem)
          (try
            (jwk/->map (parse-certificate pem))
            (catch JOSEException cert-error
              (parse-failure! "Failed to parse PEM" cert-error)))
          (parse-failure! "Failed to parse PEM" e)))
      (catch clojure.lang.ExceptionInfo e
        (throw e))
      (catch RuntimeException e
        (parse-failure! "Failed to parse PEM" e)))))

(defn- wrap64
  [^String encoded]
  (apply str (map #(str (apply str %) "\n") (partition-all 64 encoded))))

(defn- pem-block
  [label bytes]
  (str "-----BEGIN " label "-----\n"
       (wrap64 (.encodeToString (Base64/getEncoder) ^bytes bytes))
       "-----END " label "-----\n"))

(defn- public-key
  ^PublicKey [^JWK key]
  (try
    (let [key-type (.getKeyType key)]
      (cond
        (= KeyType/RSA key-type) (.toPublicKey ^RSAKey (.toRSAKey key))
        (= KeyType/EC key-type) (.toPublicKey ^ECKey (.toECKey key))
        (= KeyType/OKP key-type) (.toPublicKey ^OctetKeyPair (.toOctetKeyPair key))
        :else (invalid-option! :jwk "JWK type has no PEM public key representation" nil)))
    (catch NoClassDefFoundError e
      (throw (jose-ex :missing-optional-dep "Missing optional Tink dependency" e
                      {:dep "com.google.crypto.tink/tink"})))
    (catch JOSEException e
      (invalid-option! :jwk "JWK cannot be exported as a PEM public key" e))))

(defn- private-key
  ^PrivateKey [^JWK key]
  (when-not (.isPrivate key)
    (invalid-option! :private? "JWK has no private key material" nil))
  (try
    (let [key-type (.getKeyType key)]
      (cond
        (= KeyType/RSA key-type) (.toPrivateKey ^RSAKey (.toRSAKey key))
        (= KeyType/EC key-type) (.toPrivateKey ^ECKey (.toECKey key))
        (= KeyType/OKP key-type) (.toPrivateKey ^OctetKeyPair (.toOctetKeyPair key))
        :else (invalid-option! :jwk "JWK type has no PEM private key representation" nil)))
    (catch NoClassDefFoundError e
      (throw (jose-ex :missing-optional-dep "Missing optional Tink dependency" e
                      {:dep "com.google.crypto.tink/tink"})))
    (catch JOSEException e
      (invalid-option! :jwk "JWK cannot be exported as a PEM private key" e))))

(defn jwk->pem
  "Exports a JWK as PEM. Defaults to public SPKI PEM; pass {:private? true} for PKCS#8."
  (^String [key]
   (jwk->pem key {}))
  (^String [key opts]
   (validate-options! opts)
   (let [^JWK key (jwk/parse key)
         key-type (.getKeyType key)]
     (when (= KeyType/OCT key-type)
       (invalid-option! :jwk "Symmetric JWKs have no PEM representation" nil))
     (if (:private? opts false)
       (let [private-pem (pem-block "PRIVATE KEY" (.getEncoded (private-key key)))]
         (if (= KeyType/EC key-type)
           (str (pem-block "PUBLIC KEY" (.getEncoded (public-key key))) private-pem)
           private-pem))
       (pem-block "PUBLIC KEY" (.getEncoded (public-key key)))))))
