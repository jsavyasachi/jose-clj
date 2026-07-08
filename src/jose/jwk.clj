(ns jose.jwk
  (:require [clojure.string :as str])
  (:import (com.nimbusds.jose Algorithm JOSEException)
           (com.nimbusds.jose.jwk Curve JWK JWKSet KeyType KeyUse)
           (com.nimbusds.jose.jwk.gen ECKeyGenerator JWKGenerator
                                       OctetKeyPairGenerator
                                       OctetSequenceKeyGenerator
                                       RSAKeyGenerator)
           (java.text ParseException)
           (java.util ArrayList List Map)))

(set! *warn-on-reflection* true)

(def ^:private common-options #{:kid :use :alg})
(def ^:private type-options
  {:rsa (conj common-options :size)
   :ec (conj common-options :curve)
   :okp (conj common-options :curve)
   :oct (conj common-options :size)})

(def ^:private curves
  {:p-256 Curve/P_256
   :p-384 Curve/P_384
   :p-521 Curve/P_521
   :secp256k1 Curve/SECP256K1
   :ed25519 Curve/Ed25519
   :x25519 Curve/X25519})

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
        (invalid-option! option)))))

(defn- key-use
  [use]
  (case use
    nil nil
    :sig KeyUse/SIGNATURE
    :enc KeyUse/ENCRYPTION
    (invalid-option! :use)))

(defn- algorithm
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

(defn- configure-generator!
  [^JWKGenerator generator opts]
  (let [use (key-use (:use opts))
        alg (algorithm (:alg opts))
        kid (:kid opts)]
    (when use
      (.keyUse generator use))
    (when alg
      (.algorithm generator alg))
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

(defn private?
  [jwk]
  (let [^JWK jwk (parse jwk)]
    (.isPrivate jwk)))

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
               (.generate generator))
        :ec (let [^ECKeyGenerator generator
                  (ECKeyGenerator. (curve (:curve opts :p-256)))]
              (configure-generator! generator opts)
              (.generate generator))
        :okp (try
               (let [^OctetKeyPairGenerator generator
                     (OctetKeyPairGenerator. (curve (:curve opts :ed25519)))]
                 (configure-generator! generator opts)
                 (.generate generator))
               (catch NoClassDefFoundError e
                 (throw (jose-ex :missing-optional-dep
                                 "Missing optional Tink dependency"
                                 e
                                 {:dep "com.google.crypto.tink/tink"}))))
        :oct (let [^OctetSequenceKeyGenerator generator
                   (OctetSequenceKeyGenerator. (long (:size opts 256)))]
               (configure-generator! generator opts)
               (.generate generator)))))))

(defn jwk-set
  ^JWKSet [jwks]
  (JWKSet. (java-list (map parse jwks))))

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

(defn set->maps
  [jwks]
  (let [^JWKSet jwks (parse-set jwks)]
    (mapv ->map (.getKeys jwks))))

(defn find-key
  ^JWK [jwks kid]
  (let [^JWKSet jwks (parse-set jwks)]
    (.getKeyByKeyId jwks kid)))

(defn- public-jwk-set
  ^JWKSet [jwks]
  (let [^JWKSet jwks (parse-set jwks)]
    (jwk-set (keep public-jwk (.getKeys jwks)))))

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
