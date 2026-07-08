(ns jose.jwe
  (:require [clojure.string :as str]
            [jose.jwk :as jwk])
  (:import (com.nimbusds.jose EncryptionMethod JOSEException JOSEObjectType JWEAlgorithm JWEDecrypter JWEEncrypter
                             JWEHeader JWEHeader$Builder JWEObject KeyLengthException Payload)
           (com.nimbusds.jose.crypto AESDecrypter AESEncrypter DirectDecrypter DirectEncrypter
                                      ECDHDecrypter ECDHEncrypter RSADecrypter RSAEncrypter
                                      X25519Decrypter X25519Encrypter)
           (com.nimbusds.jose.jwk Curve ECKey JWK KeyType OctetKeyPair OctetSequenceKey RSAKey)
           (java.nio.charset StandardCharsets)
           (java.text ParseException)
           (java.util List Map)))

(set! *warn-on-reflection* true)

(def ^:private encrypt-options #{:alg :enc :kid :headers})

(def ^:private alg-names
  {:rsa-oaep-256 "RSA-OAEP-256"
   :rsa-oaep-384 "RSA-OAEP-384"
   :rsa-oaep-512 "RSA-OAEP-512"
   :ecdh-es "ECDH-ES"
   :ecdh-es+a128kw "ECDH-ES+A128KW"
   :ecdh-es+a192kw "ECDH-ES+A192KW"
   :ecdh-es+a256kw "ECDH-ES+A256KW"
   :a128kw "A128KW"
   :a192kw "A192KW"
   :a256kw "A256KW"
   :a128gcmkw "A128GCMKW"
   :a192gcmkw "A192GCMKW"
   :a256gcmkw "A256GCMKW"
   :dir "dir"})

(def ^:private enc-names
  {:a128cbc-hs256 "A128CBC-HS256"
   :a192cbc-hs384 "A192CBC-HS384"
   :a256cbc-hs512 "A256CBC-HS512"
   :a128gcm "A128GCM"
   :a192gcm "A192GCM"
   :a256gcm "A256GCM"})

(def ^:private name-algs
  (into {} (map (fn [[k v]] [v k]) alg-names)))

(def ^:private name-encs
  (into {} (map (fn [[k v]] [v k]) enc-names)))

(defn- jose-ex
  [error message cause data]
  (ex-info message (assoc data :jose/error error) cause))

(defn- invalid-option!
  [option]
  (throw (ex-info (str "Invalid option " option)
                  {:jose/error :invalid-option
                   :option option})))

(defn- invalid-rsa1-5! []
  (throw (ex-info "Invalid option :rsa1-5; use :rsa-oaep-256 instead"
                  {:jose/error :invalid-option
                   :option :alg})))

(defn- validate-options!
  [opts]
  (doseq [option (keys opts)]
    (cond
      (= :rsa1-5 option) (invalid-rsa1-5!)
      (not (contains? encrypt-options option)) (invalid-option! option))))

(defn- algorithm
  ^JWEAlgorithm [alg]
  (cond
    (#{:rsa1-5 "RSA1_5" "RSA1-5"} alg) (invalid-rsa1-5!)
    (instance? JWEAlgorithm alg) alg
    (keyword? alg) (JWEAlgorithm/parse ^String (get alg-names alg (str/upper-case (name alg))))
    (string? alg) (JWEAlgorithm/parse ^String alg)
    :else (invalid-option! :alg)))

(defn- encryption-method
  ^EncryptionMethod [enc]
  (cond
    (instance? EncryptionMethod enc) enc
    (keyword? enc) (EncryptionMethod/parse ^String (get enc-names enc (str/upper-case (name enc))))
    (string? enc) (EncryptionMethod/parse ^String enc)
    :else (invalid-option! :enc)))

(defn- alg-keyword
  [alg]
  (let [name (str alg)]
    (get name-algs name (keyword (str/lower-case name)))))

(defn- enc-keyword
  [enc]
  (let [name (str enc)]
    (get name-encs name (keyword (str/lower-case name)))))

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
  [^JWEHeader header]
  (-> (keywordize-json-value (.toJSONObject header))
      (update :alg alg-keyword)
      (update :enc enc-keyword)))

(defn- ->payload
  ^Payload [payload]
  (cond
    (string? payload) (Payload. ^String payload)
    (bytes? payload) (Payload. ^bytes payload)
    :else (throw (ex-info "Expected string or bytes payload"
                          {:jose/error :invalid-option
                           :option :payload}))))

(defn- oct-byte-length
  [^OctetSequenceKey key]
  (alength (.toByteArray key)))

(defn- default-oct-alg
  [^OctetSequenceKey key]
  (let [length (oct-byte-length key)]
    (cond
      (= 16 length) :a128kw
      (= 24 length) :a192kw
      (= 32 length) :a256kw
      :else (throw (jose-ex :key-length "Unsupported oct key length" nil {})))))

(defn- default-alg
  [^JWK key]
  (let [key-type (.getKeyType key)]
    (cond
      (= KeyType/RSA key-type) :rsa-oaep-256
      (= KeyType/EC key-type) :ecdh-es
      (= KeyType/OCT key-type) (default-oct-alg (.toOctetSequenceKey key))
      (= KeyType/OKP key-type) (if (= Curve/X25519 (.getCurve (.toOctetKeyPair key)))
                                 :ecdh-es
                                 (invalid-option! :alg))
      :else (invalid-option! :alg))))

(defn- public-key
  ^JWK [^JWK key]
  (or (jwk/public-jwk key) key))

(defn- encrypter
  ^JWEEncrypter [^JWK key]
  (let [key-type (.getKeyType key)]
    (cond
      (= KeyType/RSA key-type) (RSAEncrypter. ^RSAKey (.toRSAKey (public-key key)))
      (= KeyType/EC key-type) (ECDHEncrypter. ^ECKey (.toECKey (public-key key)))
      (= KeyType/OCT key-type) (AESEncrypter. ^OctetSequenceKey (.toOctetSequenceKey key))
      (= KeyType/OKP key-type) (let [okp (.toOctetKeyPair (public-key key))]
                                 (if (= Curve/X25519 (.getCurve okp))
                                   (X25519Encrypter. ^OctetKeyPair okp)
                                   (invalid-option! :alg)))
      :else (invalid-option! :alg))))

(defn- decrypter
  ^JWEDecrypter [^JWK key ^JWEHeader header]
  (let [key-type (.getKeyType key)
        alg (.getAlgorithm header)]
    (cond
      (= KeyType/RSA key-type) (RSADecrypter. ^RSAKey (.toRSAKey key))
      (= KeyType/EC key-type) (ECDHDecrypter. ^ECKey (.toECKey key))
      (= KeyType/OKP key-type) (let [okp (.toOctetKeyPair key)]
                                 (if (= Curve/X25519 (.getCurve okp))
                                   (X25519Decrypter. ^OctetKeyPair okp)
                                   (invalid-option! :alg)))
      (= JWEAlgorithm/DIR alg) (DirectDecrypter. ^OctetSequenceKey (.toOctetSequenceKey key))
      (= KeyType/OCT key-type) (AESDecrypter. ^OctetSequenceKey (.toOctetSequenceKey key))
      :else (invalid-option! :alg))))

(defn- jwe-object
  ^JWEObject [compact]
  (try
    (JWEObject/parse ^String compact)
    (catch ParseException e
      (throw (jose-ex :parse-failure "Failed to parse JWE" e {})))
    (catch RuntimeException e
      (throw (jose-ex :parse-failure "Failed to parse JWE" e {})))))

(defn- apply-header!
  [^JWEHeader$Builder builder k v]
  (case k
    :typ (.type builder (JOSEObjectType. (str v)))
    :cty (.contentType builder (str v))
    (.customParam builder (name k) (stringify-json-value v))))

(defn- direct-alg?
  [^JWEAlgorithm alg]
  (= JWEAlgorithm/DIR alg))

(defn- direct-encrypter?
  [^JWEAlgorithm alg]
  (= JWEAlgorithm/DIR alg))

(defn- build-encrypter
  ^JWEEncrypter [^JWK key ^JWEAlgorithm alg]
  (if (direct-encrypter? alg)
    (DirectEncrypter. ^OctetSequenceKey (.toOctetSequenceKey key))
    (encrypter key)))

(defn- key-length-exception?
  [^JOSEException e]
  (let [message (ex-message e)]
    (boolean (and message
                  (or (str/includes? message "The Key Encryption Method")
                      (str/includes? message "key length")
                      (str/includes? message "Key length")
                      (str/includes? message "not supported by the JWE encrypter"))))))

(defn encrypt
  "Encrypts a string or byte-array payload and returns a compact JWE string."
  (^String [key payload-value]
   (encrypt key payload-value {}))
  (^String [key payload-value opts]
   (validate-options! opts)
   (try
     (let [^JWK key (jwk/parse key)
           alg (algorithm (:alg opts (default-alg key)))
           enc (encryption-method (:enc opts :a256gcm))
           ^JWEHeader$Builder builder (JWEHeader$Builder. alg enc)
           kid (if (contains? opts :kid) (:kid opts) (.getKeyID key))]
       (when (and (direct-alg? alg)
                  (not= KeyType/OCT (.getKeyType key)))
         (invalid-option! :alg))
       (doseq [[k v] (:headers opts)]
         (apply-header! builder k v))
       (when kid
         (.keyID builder kid))
       (let [jwe (JWEObject. (.build builder) (->payload payload-value))]
         (.encrypt jwe (build-encrypter key alg))
         (.serialize jwe)))
     (catch KeyLengthException e
       (throw (jose-ex :key-length "Invalid JWE key length" e {})))
     (catch JOSEException e
       (if (key-length-exception? e)
         (throw (jose-ex :key-length "Invalid JWE key length" e {}))
         (throw (jose-ex :encryption-failure "Failed to encrypt JWE" e {})))))))

(defn decrypt
  "Decrypts a compact JWE and returns {:payload string :payload-bytes bytes :header map}."
  [key compact]
  (try
    (let [jwe (jwe-object compact)
          ^JWEHeader header (.getHeader jwe)]
      (.decrypt jwe (decrypter (jwk/parse key) header))
      (let [^Payload payload (.getPayload jwe)
            bytes (.toBytes payload)]
        {:payload (String. ^bytes bytes StandardCharsets/UTF_8)
         :payload-bytes bytes
         :header (header-map header)}))
    (catch KeyLengthException e
      (throw (jose-ex :key-length "Invalid JWE key length" e {})))
    (catch JOSEException e
      (throw (jose-ex :decryption-failure "Failed to decrypt JWE" e {})))))

(defn header
  "Returns the unverified compact JWE header as a Clojure map."
  [compact]
  (header-map (.getHeader (jwe-object compact))))
