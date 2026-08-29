(ns jose.proc
  (:require [clojure.string :as str]
            [jose.jwk :as jwk]
            [jose.jwks :as jwks])
  (:import (com.nimbusds.jose Algorithm EncryptionMethod JOSEException JOSEObject JOSEObjectType
                               JWSAlgorithm JWSAlgorithm$Family JWSHeader JWEAlgorithm JWEHeader
                               JWSObject JWEObject Payload)
           (com.nimbusds.jose.jwk ECKey JWK JWKSet JWKSelector OctetKeyPair OctetSequenceKey RSAKey)
           (com.nimbusds.jose.jwk.source ImmutableJWKSet JWKSource)
           (com.nimbusds.jose.proc BadJOSEException BadJWEException BadJWSException
                                    ConfigurableJOSEProcessor DefaultJOSEObjectTypeVerifier
                                    DefaultJOSEProcessor JWEDecryptionKeySelector JWEKeySelector
                                    JWKSecurityContext JOSEMatcher JWSAlgorithmFamilyJWSKeySelector
                                    JWSKeySelector JWSVerificationKeySelector SecurityContext
                                    SingleKeyJWSKeySelector JWEDecrypterFactory
                                    JWSVerifierFactory)
           (com.nimbusds.jose.crypto.factories DefaultJWEDecrypterFactory
                                               DefaultJWSVerifierFactory)
           (jose.jwks Source)
           (java.net URI URL)
           (java.nio.charset StandardCharsets)
           (java.security Key)
           (java.text ParseException)
           (java.util ArrayList HashSet List Set)))

(set! *warn-on-reflection* true)

(defrecord Processor [^ConfigurableJOSEProcessor processor jws-algs jwe-algs encs typ
                      jws-configured? jwe-configured? jws-policy?
                      ^JWSVerifierFactory jws-verifier-factory
                      ^JWEDecrypterFactory jwe-decrypter-factory])

(def ^:private processor-options
  #{:jws-alg :jws-algs :jwe-alg :jwe-algs :jwe-enc :jwe-encs :typ
    :jws-key-selector :jwe-key-selector :jws-verifier-factory
    :jwe-decrypter-factory})

(def ^:private family-values
  {:hmac-sha JWSAlgorithm$Family/HMAC_SHA
   :rsa JWSAlgorithm$Family/RSA
   :ec JWSAlgorithm$Family/EC
   :ed JWSAlgorithm$Family/ED
   :signature JWSAlgorithm$Family/SIGNATURE})

(def ^:private jws-algorithm-values
  {:hs256 JWSAlgorithm/HS256 :hs384 JWSAlgorithm/HS384 :hs512 JWSAlgorithm/HS512
   :rs256 JWSAlgorithm/RS256 :rs384 JWSAlgorithm/RS384 :rs512 JWSAlgorithm/RS512
   :ps256 JWSAlgorithm/PS256 :ps384 JWSAlgorithm/PS384 :ps512 JWSAlgorithm/PS512
   :es256 JWSAlgorithm/ES256 :es256k JWSAlgorithm/ES256K :es384 JWSAlgorithm/ES384
   :es512 JWSAlgorithm/ES512 :eddsa JWSAlgorithm/EdDSA :ed25519 JWSAlgorithm/Ed25519})

(def ^:private jwe-algorithm-values
  {:rsa-oaep-256 JWEAlgorithm/RSA_OAEP_256 :rsa-oaep-384 JWEAlgorithm/RSA_OAEP_384
   :rsa-oaep-512 JWEAlgorithm/RSA_OAEP_512 :a128kw JWEAlgorithm/A128KW
   :a192kw JWEAlgorithm/A192KW :a256kw JWEAlgorithm/A256KW :dir JWEAlgorithm/DIR
   :ecdh-es JWEAlgorithm/ECDH_ES :ecdh-es+a128kw JWEAlgorithm/ECDH_ES_A128KW
   :ecdh-es+a192kw JWEAlgorithm/ECDH_ES_A192KW :ecdh-es+a256kw JWEAlgorithm/ECDH_ES_A256KW
   :ecdh-1pu JWEAlgorithm/ECDH_1PU :ecdh-1pu+a128kw JWEAlgorithm/ECDH_1PU_A128KW
   :ecdh-1pu+a192kw JWEAlgorithm/ECDH_1PU_A192KW :ecdh-1pu+a256kw JWEAlgorithm/ECDH_1PU_A256KW
   :a128gcmkw JWEAlgorithm/A128GCMKW :a192gcmkw JWEAlgorithm/A192GCMKW
   :a256gcmkw JWEAlgorithm/A256GCMKW :pbes2-hs256+a128kw JWEAlgorithm/PBES2_HS256_A128KW
   :pbes2-hs384+a192kw JWEAlgorithm/PBES2_HS384_A192KW
   :pbes2-hs512+a256kw JWEAlgorithm/PBES2_HS512_A256KW})

(def ^:private encryption-method-values
  {:a128cbc-hs256 EncryptionMethod/A128CBC_HS256 :a192cbc-hs384 EncryptionMethod/A192CBC_HS384
   :a256cbc-hs512 EncryptionMethod/A256CBC_HS512 :a128gcm EncryptionMethod/A128GCM
   :a192gcm EncryptionMethod/A192GCM :a256gcm EncryptionMethod/A256GCM :xc20p EncryptionMethod/XC20P})

(defn- jose-ex [error message cause data]
  (ex-info message (assoc data :jose/error error) cause))

(defn- invalid-option! [option]
  (throw (ex-info (str "Invalid option " option)
                  {:jose/error :invalid-option :option option})))

(defn- validate-options! [opts]
  (when-not (map? opts) (invalid-option! :policy))
  (doseq [option (keys opts)]
    (when-not (contains? processor-options option)
      (invalid-option! option))))

(defn- source ^JWKSource [value]
  (cond
    (instance? Source value) (:jwk-source value)
    (instance? JWKSource value) value
    :else (invalid-option! :source)))

(defn- jws-algorithm ^JWSAlgorithm [value]
  (cond
    (instance? JWSAlgorithm value) value
    (keyword? value) (if-let [algorithm (get jws-algorithm-values value)]
                       algorithm
                       (invalid-option! :jws-algs))
    (string? value) (JWSAlgorithm/parse ^String value)
    :else (invalid-option! :jws-algs)))

(defn- jwe-algorithm ^JWEAlgorithm [value]
  (cond
    (instance? JWEAlgorithm value) value
    (keyword? value) (if-let [algorithm (get jwe-algorithm-values value)]
                       algorithm
                       (invalid-option! :jwe-algs))
    (string? value) (JWEAlgorithm/parse ^String value)
    :else (invalid-option! :jwe-algs)))

(defn- encryption-method ^EncryptionMethod [value]
  (cond
    (instance? EncryptionMethod value) value
    (keyword? value) (if-let [method (get encryption-method-values value)]
                       method
                       (invalid-option! :jwe-encs))
    (string? value) (EncryptionMethod/parse ^String value)
    :else (invalid-option! :jwe-encs)))

(defn- values [opts singular plural option]
  (when (and (contains? opts singular) (contains? opts plural))
    (invalid-option! singular))
  (let [value (if (contains? opts plural) (get opts plural) (get opts singular))]
    (when (nil? value) (invalid-option! plural))
    (let [result (if (or (sequential? value) (set? value)) value [value])]
      (when (empty? result) (invalid-option! option))
      result)))

(defn- context-source
  ^JWKSource [^JWKSource fallback]
  (reify JWKSource
    (^List get [_ ^JWKSelector selector ^SecurityContext context]
      (if (instance? JWKSecurityContext context)
        (.get (ImmutableJWKSet. (JWKSet. ^List (.getKeys ^JWKSecurityContext context)))
              selector context)
        (.get fallback selector context)))))

(defn jws-key-selector
  "Builds a JWS key selector from a JWS algorithm family and JWKS source.

  The family may be a keyword such as :rsa or a Nimbus JWSAlgorithm$Family.
  The source may be a jose.jwks Source or a Nimbus JWKSource. The returned
  selector also consults a per-call JWKSecurityContext when supplied."
  (^JWSKeySelector [family source-value]
   (let [family (if (keyword? family)
                  (if-let [value (get family-values family)] value (invalid-option! :family))
                  family)
         source (when source-value (source source-value))]
     (when-not (instance? JWSAlgorithm$Family family) (invalid-option! :family))
     (try
       (JWSAlgorithmFamilyJWSKeySelector. ^JWSAlgorithm$Family family
                                          (context-source source))
       (catch RuntimeException e
         (throw (jose-ex :key-source-failure "Failed to create JWS key selector" e {})))))))

(defn jws-key-selector-from-jwk-set-url
  "Builds Nimbus's signature-family selector from a JWKS URL."
  ^JWSKeySelector [url]
  ;; Nimbus's URL factory owns its RemoteJWKSet and cannot use per-call keys.
  (try
    (JWSAlgorithmFamilyJWSKeySelector/fromJWKSetURL ^URL url)
    (catch RuntimeException e
      (throw (jose-ex :key-source-failure "Failed to create JWS key selector" e {})))))

(defn single-key-selector
  "Builds a JWS key selector for one algorithm and Java key or JWK."
  ^JWSKeySelector [alg key]
  (let [^JWK parsed (when-not (instance? Key key) (jwk/parse key))
        ^Key key (if (instance? Key key)
                   key
                   (try
                     (cond
                       (= "oct" (str/lower-case (str (.getKeyType parsed))))
                       (.toSecretKey ^OctetSequenceKey (.toOctetSequenceKey parsed))
                       (= "RSA" (str (.getKeyType parsed))) (.toPublicKey ^RSAKey (.toRSAKey parsed))
                       (= "EC" (str (.getKeyType parsed))) (.toPublicKey ^ECKey (.toECKey parsed))
                       (= "OKP" (str (.getKeyType parsed))) (.toPublicKey ^OctetKeyPair (.toOctetKeyPair parsed))
                       :else (invalid-option! :key))
                     (catch JOSEException e
                       (throw (jose-ex :key-import-failure "Failed to import JWK key" e {})))))]
    (SingleKeyJWSKeySelector. (jws-algorithm alg) key)))

(defn security-context
  "Builds a per-call Nimbus JWK security context from JWKs or JWK maps."
  ^JWKSecurityContext [keys]
  (try
    (JWKSecurityContext. (ArrayList. ^java.util.Collection (map jwk/parse keys)))
    (catch RuntimeException e
      (throw (jose-ex :key-import-failure "Failed to import security-context keys" e {})))))

(defn- type-verifier ^DefaultJOSEObjectTypeVerifier [typ]
  (let [^Set types #{(JOSEObjectType. (str typ))}]
    (DefaultJOSEObjectTypeVerifier. types)))

(defn- jwe-selector ^JWEKeySelector [source-value algorithms encryptions]
  (let [source (context-source (source source-value))]
    (reify JWEKeySelector
      (^List selectJWEKeys [_ ^JWEHeader header ^SecurityContext context]
        (if (and (contains? algorithms (.getAlgorithm header))
                 (contains? encryptions (.getEncryptionMethod header)))
          (.selectJWEKeys (JWEDecryptionKeySelector. (.getAlgorithm header)
                                                      (.getEncryptionMethod header)
                                                      source)
                          header context)
          (ArrayList.))))))

(defn processor
  "Builds a configurable generic JOSE processor for signed or encrypted JOSE."
  ^Processor [source-value opts]
  (validate-options! opts)
  (let [jws-configured? (or (contains? opts :jws-alg) (contains? opts :jws-algs)
                            (contains? opts :jws-key-selector)
                            (contains? opts :jws-verifier-factory))
        jwe-configured? (or (contains? opts :jwe-alg) (contains? opts :jwe-algs)
                            (contains? opts :jwe-enc) (contains? opts :jwe-encs)
                            (contains? opts :jwe-key-selector)
                            (contains? opts :jwe-decrypter-factory))
        _ (when-not (or jws-configured? jwe-configured?) (invalid-option! :policy))
        jws-values (when (or (contains? opts :jws-alg) (contains? opts :jws-algs))
                      (values opts :jws-alg :jws-algs :jws-algs))
        jwe-values (when (or (contains? opts :jwe-alg) (contains? opts :jwe-algs))
                     (values opts :jwe-alg :jwe-algs :jwe-algs))
        enc-values (when (or (contains? opts :jwe-enc) (contains? opts :jwe-encs))
                      (values opts :jwe-enc :jwe-encs :jwe-encs))
        _ (when (and (or jwe-values enc-values)
                     (or (nil? jwe-values) (nil? enc-values)))
            (invalid-option! (if (nil? jwe-values) :jwe-algs :jwe-encs)))
        jws-algs (when jws-values (set (map jws-algorithm jws-values)))
        jwe-algs (when jwe-values (set (map jwe-algorithm jwe-values)))
        encs (when enc-values (set (map encryption-method enc-values)))
        ^JWSVerifierFactory jws-verifier-factory
        (if (contains? opts :jws-verifier-factory)
          (:jws-verifier-factory opts)
          (DefaultJWSVerifierFactory.))
        ^JWEDecrypterFactory jwe-decrypter-factory
        (if (contains? opts :jwe-decrypter-factory)
          (:jwe-decrypter-factory opts)
          (DefaultJWEDecrypterFactory.))
        processor (DefaultJOSEProcessor.)]
    (when-not (instance? JWSVerifierFactory jws-verifier-factory)
      (invalid-option! :jws-verifier-factory))
    (when-not (instance? JWEDecrypterFactory jwe-decrypter-factory)
      (invalid-option! :jwe-decrypter-factory))
    (.setJWSVerifierFactory processor jws-verifier-factory)
    (.setJWEDecrypterFactory processor jwe-decrypter-factory)
    (when (and jws-configured? (or (:jws-key-selector opts) jws-algs))
      (if-let [selector (:jws-key-selector opts)]
        (if (instance? JWSKeySelector selector)
          (.setJWSKeySelector processor selector)
          (invalid-option! :jws-key-selector))
        (.setJWSKeySelector processor
                            (JWSVerificationKeySelector. ^Set jws-algs (context-source (source source-value))))))
    (when (and jwe-configured? (or (:jwe-key-selector opts) (and jwe-algs encs)))
      (if-let [selector (:jwe-key-selector opts)]
        (if (instance? JWEKeySelector selector)
          (.setJWEKeySelector processor selector)
          (invalid-option! :jwe-key-selector))
        (when (and jwe-algs encs)
          (.setJWEKeySelector processor (jwe-selector source-value jwe-algs encs)))))
    (when (contains? opts :typ)
      (let [verifier (type-verifier (:typ opts))]
        (.setJWSTypeVerifier processor verifier)
        (.setJWETypeVerifier processor verifier)))
    (->Processor processor jws-algs jwe-algs encs (:typ opts)
                 jws-configured? jwe-configured?
                 (and jws-configured? (not (:jws-key-selector opts)))
                 jws-verifier-factory jwe-decrypter-factory)))

(defn jws-verifier-factory
  "Returns the Nimbus verifier factory configured on a processor."
  ^JWSVerifierFactory [^Processor processor]
  (:jws-verifier-factory processor))

(defn jwe-decrypter-factory
  "Returns the Nimbus decrypter factory configured on a processor."
  ^JWEDecrypterFactory [^Processor processor]
  (:jwe-decrypter-factory processor))

(defn- payload-map [^Payload payload]
  (let [^bytes bytes (.toBytes payload)]
    {:payload (String. bytes StandardCharsets/UTF_8)
     :payload-bytes bytes}))

(defn- preflight
  [^Processor handle ^String compact]
  (let [object (try
                 (JOSEObject/parse compact)
                 (catch ParseException e
                   (throw (jose-ex :parse-failure "Failed to parse JOSE" e {}))))
        header (.getHeader ^JOSEObject object)]
    (cond
      (not (or (instance? JWSObject object) (instance? JWEObject object)))
      (throw (jose-ex :unsecured-plain "Unsecured plain JOSE objects are rejected" nil {}))
      (instance? JWSObject object)
      (do
        (when-not (:jws-configured? handle)
          (throw (jose-ex :key-not-found "No JWS key selector is configured" nil {})))
        (when (and (:jws-policy? handle) (:jws-algs handle)
                   (not (contains? (:jws-algs handle) (.getAlgorithm header))))
          (throw (jose-ex :algorithm-not-allowed "JWS algorithm is not allowed" nil
                          {:alg (.getAlgorithm header)}))))
      :else
      (do
        (when-not (:jwe-configured? handle)
          (throw (jose-ex :key-not-found "No JWE key selector is configured" nil {})))
        (when (and (:jwe-algs handle)
                   (not (contains? (:jwe-algs handle) (.getAlgorithm header))))
          (throw (jose-ex :algorithm-not-allowed "JWE algorithm is not allowed" nil
                          {:alg (.getAlgorithm header)})))
        (when (and (:encs handle)
                   (not (contains? (:encs handle) (.getEncryptionMethod ^JWEHeader header))))
          (throw (jose-ex :algorithm-not-allowed "JWE encryption method is not allowed" nil
                          {:enc (.getEncryptionMethod ^JWEHeader header)})))))
    (when (and (:typ handle)
               (not= (str (:typ handle)) (some-> (.getType header) str)))
      (throw (jose-ex :header-mismatch "JOSE typ header does not match" nil
                      {:header :typ :expected (str (:typ handle)) :actual (.getType header)})))
    object))

(defn process
  "Processes compact JOSE with a processor and returns payload text and bytes."
  ([^Processor processor ^String compact]
   (process processor compact nil))
  ([^Processor processor ^String compact context]
   (let [^SecurityContext context (if (or (nil? context) (instance? SecurityContext context))
                                    context
                                    (security-context context))]
     (try
       (preflight processor compact)
       (payload-map (.process ^ConfigurableJOSEProcessor (:processor processor) compact context))
       (catch BadJWSException e
         (throw (jose-ex :invalid-signature "Failed to process JWS" e {})))
       (catch BadJWEException e
         (throw (jose-ex :decryption-failure "Failed to decrypt JWE" e {})))
       (catch BadJOSEException e
         (throw (jose-ex :key-not-found "Failed to process JOSE" e {})))
       (catch ParseException e
         (throw (jose-ex :parse-failure "Failed to parse JOSE" e {})))
       (catch JOSEException e
         (throw (jose-ex :decryption-failure "Failed to process JOSE" e {})))))))

(defn- matcher-set [value converter]
  (when value (HashSet. ^java.util.Collection (map converter value))))

(defn matcher
  "Returns a predicate matching JOSE objects against supplied criteria.

  Criteria are :classes, :algorithms, :encryption-methods, :jwk-urls, and
  :key-ids. The predicate accepts a Nimbus JOSEObject or compact string."
  [opts]
  (let [allowed #{:classes :algorithms :encryption-methods :jwk-urls :key-ids}]
    (doseq [option (keys opts)] (when-not (contains? allowed option) (invalid-option! option)))
    (let [classes (matcher-set (:classes opts)
                               #(if (instance? Class %)
                                  %
                                  (case %
                                    :jose JOSEObject
                                    :jws JWSObject
                                    :jwe JWEObject
                                    :plain com.nimbusds.jose.PlainObject
                                    (invalid-option! :classes))))
          algorithms (matcher-set (:algorithms opts)
                                  #(if (instance? Algorithm %)
                                     %
                                     (if (keyword? %)
                                       (or (get jws-algorithm-values %)
                                           (get jwe-algorithm-values %)
                                           (invalid-option! :algorithms))
                                       (Algorithm/parse ^String (str %)))))
          encryptions (matcher-set (:encryption-methods opts)
                                   #(if (instance? EncryptionMethod %) %
                                      (if (keyword? %)
                                        (if-let [method (get encryption-method-values %)]
                                          method
                                          (invalid-option! :encryption-methods))
                                        (EncryptionMethod/parse ^String (str %)))))
          urls (matcher-set (:jwk-urls opts) #(URI. (str %)))
          kids (matcher-set (:key-ids opts) str)
          delegate (JOSEMatcher. classes algorithms encryptions urls kids)]
      (fn [value]
        (try
          (.matches delegate (if (instance? JOSEObject value) value (JOSEObject/parse ^String value)))
          (catch ParseException _ false))))))

(def jws-algorithm-families (set (keys family-values)))
