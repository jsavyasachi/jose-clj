(ns jose.keyring
  (:require [jose.jwe :as jwe]
            [jose.jwk :as jwk]
            [jose.jws :as jws])
  (:import (com.nimbusds.jose.jwk JWK JWKSet)
           (java.time Instant)))

(set! *warn-on-reflection* true)

(defrecord KeyRing [keys active-signing-kid active-encryption-kid retired-at])

(def ^:private key-ring-options #{:active-signing-kid :active-encryption-kid})
(def ^:private prune-options #{:retention-seconds :now})
(def ^:private rotate-options #{:at})

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

(defn- require-key!
  ^JWK [keys kid role]
  (or (get keys kid)
      (throw (ex-info (str "Active " (name role) " key not found")
                      {:jose/error :key-not-found
                       :kid kid
                       :role role}))))

(defn key-ring
  "Creates an immutable key ring from JWKs and active signing/encryption kids."
  [keys opts]
  (validate-options! key-ring-options opts)
  (let [parsed (mapv jwk/parse keys)
        by-kid (into {} (map (fn [^JWK key]
                               (let [kid (.getKeyID key)]
                                 (when-not kid
                                   (throw (ex-info "Key ring keys require kid"
                                                   {:jose/error :invalid-option
                                                    :option :kid})))
                                 [kid key]))
                             parsed))
        signing-kid (:active-signing-kid opts)
        encryption-kid (:active-encryption-kid opts)]
    (when-not (= (count parsed) (count by-kid))
      (throw (ex-info "Key ring kids must be unique"
                      {:jose/error :invalid-option
                       :option :kid})))
    (require-key! by-kid signing-kid :signing)
    (require-key! by-kid encryption-kid :encryption)
    (->KeyRing by-kid signing-kid encryption-kid {})))

(defn sign
  "Signs with the active signing key."
  ([ring payload]
   (sign ring payload {}))
  ([^KeyRing ring payload opts]
   (jws/sign (require-key! (:keys ring) (:active-signing-kid ring) :signing)
             payload
             opts)))

(defn encrypt
  "Encrypts with the active encryption key."
  ([ring payload]
   (encrypt ring payload {}))
  ([^KeyRing ring payload opts]
   (jwe/encrypt (require-key! (:keys ring) (:active-encryption-kid ring) :encryption)
                payload
                opts)))

(defn- candidate-keys
  [^KeyRing ring kid]
  (let [preferred (get (:keys ring) kid)]
    (cond->> (vals (:keys ring))
      preferred (cons preferred)
      preferred distinct)))

(defn- try-keys
  [keys f error message]
  (loop [[key & remaining] keys
         first-failure nil]
    (if key
      (let [[status value] (try
                             [:ok (f key)]
                             (catch RuntimeException e
                               [:error e]))]
        (if (= :ok status)
          value
          (recur remaining (or first-failure value))))
      (throw (ex-info message {:jose/error error} first-failure)))))

(defn verify
  "Verifies with the header kid first, then falls back across retained keys."
  ([ring compact]
   (verify ring compact {}))
  ([^KeyRing ring compact opts]
   (let [kid (:kid (jws/header compact))]
     (try-keys (candidate-keys ring kid)
               #(jws/verify % compact opts)
               :invalid-signature
               "No key in the ring verified the JWS"))))

(defn decrypt
  "Decrypts with the header kid first, then falls back across retained keys."
  [^KeyRing ring compact]
  (let [kid (:kid (jwe/header compact))]
    (try-keys (candidate-keys ring kid)
              #(jwe/decrypt % compact)
              :decryption-failure
              "No key in the ring decrypted the JWE")))

(defn rotate
  "Promotes a new active key for :signing or :encryption and retains the old key."
  ([ring role key]
   (rotate ring role key {}))
  ([^KeyRing ring role key opts]
   (validate-options! rotate-options opts)
   (let [^JWK key (jwk/parse key)
         kid (.getKeyID key)
         active-field (case role
                        :signing :active-signing-kid
                        :encryption :active-encryption-kid
                        (invalid-option! :role))
         old-kid (get ring active-field)
         at (long (:at opts (.getEpochSecond (Instant/now))))]
     (when-not kid
       (throw (ex-info "Key ring keys require kid"
                       {:jose/error :invalid-option
                        :option :kid})))
     (-> ring
         (assoc-in [:keys kid] key)
         (assoc active-field kid)
         (assoc-in [:retired-at old-kid] at)
         (update :retired-at dissoc kid)))))

(defn prune
  "Drops non-active keys retired before the configured retention window."
  [^KeyRing ring opts]
  (validate-options! prune-options opts)
  (let [retention (:retention-seconds opts)
        now (long (:now opts (.getEpochSecond (Instant/now))))]
    (when-not (and (integer? retention) (not (neg? retention)))
      (invalid-option! :retention-seconds))
    (let [cutoff (- now retention)
          active (hash-set (:active-signing-kid ring) (:active-encryption-kid ring))
          expired (into #{}
                        (keep (fn [[kid retired-at]]
                                (when (and (not (contains? active kid))
                                           (<= (long retired-at) cutoff))
                                  kid)))
                        (:retired-at ring))]
      (-> ring
          (update :keys #(apply dissoc % expired))
          (update :retired-at #(apply dissoc % expired))))))

(defn public-jwks
  "Returns a Nimbus JWKSet containing only public key material."
  ^JWKSet [^KeyRing ring]
  (jwk/jwk-set (keep jwk/public-jwk (vals (:keys ring)))))

(defn public-jwks-json
  "Returns the public key ring as JWKS JSON suitable for publication."
  ^String [ring]
  (jwk/set->json (public-jwks ring)))
