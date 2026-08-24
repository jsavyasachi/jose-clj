(ns jose.property-test
  (:require [clojure.test :refer [is]]
            [jose.jwk :as jwk]
            [jose.jwks :as jwks]
            [jose.jwe :as jwe]
            [jose.jws :as jws]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  (:import (clojure.lang ExceptionInfo)
           (com.sun.net.httpserver HttpHandler HttpServer)
           (java.net InetSocketAddress)
           (java.nio.charset StandardCharsets)))

(def payload-gen
  (gen/fmap #(apply str %) (gen/vector gen/char-alphanumeric 1 80)))

(def compact-gen
  (gen/fmap #(apply str %) (gen/vector gen/char 0 120)))

(defn thrown
  [f]
  (try
    {:value (f)}
    (catch Throwable e
      {:throwable e})))

(defn expected-library-failure?
  [{:keys [throwable]}]
  (and (instance? ExceptionInfo throwable)
       (contains? #{:parse-failure :invalid-signature :algorithm-not-allowed
                    :key-not-found :ambiguous-key}
                   (:jose/error (ex-data throwable)))))

(defspec malformed-compact-inputs-have-typed-failures
  {:num-tests 20 :seed 424242}
  (prop/for-all [compact compact-gen]
    (expected-library-failure?
     (thrown #(jws/verify (jwk/generate :oct {:size 256}) compact
                          {:algs #{:hs256}})))))

(defspec unexpected-signing-algorithms-are-rejected
  {:num-tests 12 :seed 424243}
  (prop/for-all [payload payload-gen
                [signed-alg expected-alg] (gen/elements [[:hs256 :hs384]
                                                           [:hs384 :hs512]
                                                           [:hs512 :hs256]])]
    (let [key (jwk/generate :oct {:size 512})
          compact (jws/sign key payload {:alg signed-alg})
          result (thrown #(jws/verify key compact {:alg expected-alg}))]
      (and (instance? ExceptionInfo (:throwable result))
           (= :algorithm-not-allowed
              (:jose/error (ex-data (:throwable result))))))))

(defspec signing-round-trips-preserve-payloads
  {:num-tests 12 :seed 424244}
  (prop/for-all [payload payload-gen
                kind (gen/elements [:rsa :ec :oct :okp])]
    (let [[key alg] (case kind
                      :rsa [(jwk/generate :rsa {:size 2048}) :rs256]
                      :ec [(jwk/generate :ec {:curve :p-256}) :es256]
                      :oct [(jwk/generate :oct {:size 256}) :hs256]
                      :okp [(jwk/generate :okp {:curve :ed25519}) :eddsa])
          compact (jws/sign key payload {:alg alg})
          verification-key (if (= :oct kind) key (jwk/public-jwk key))]
      (= payload (:payload (jws/verify verification-key compact {:alg alg}))))))

(defspec encryption-round-trips-preserve-payloads
  {:num-tests 8 :seed 424245}
  (prop/for-all [payload payload-gen
                kind (gen/elements [:rsa :ec :x25519 :oct])]
    (let [[key opts] (case kind
                       :rsa [(jwk/generate :rsa {:size 2048})
                             {:alg :rsa-oaep-256 :enc :a256gcm}]
                       :ec [(jwk/generate :ec {:curve :p-256})
                            {:alg :ecdh-es :enc :a256gcm}]
                       :x25519 [(jwk/generate :okp {:curve :x25519})
                                {:alg :ecdh-es :enc :a256gcm}]
                       :oct [(jwk/generate :oct {:size 256})
                             {:alg :dir :enc :a256gcm}])
          compact (jwe/encrypt key payload opts)]
      (= payload (:payload (jwe/decrypt key compact))))))

(defn rotation-server
  [body]
  (let [server (HttpServer/create (InetSocketAddress. "127.0.0.1" 0) 0)]
    (.createContext server "/jwks"
                    (reify HttpHandler
                      (handle [_ exchange]
                        (let [bytes (.getBytes ^String @body StandardCharsets/UTF_8)]
                          (.sendResponseHeaders exchange 200 (count bytes))
                          (with-open [^java.io.OutputStream output (.getResponseBody exchange)]
                            (.write output bytes))))))
    (.start server)
    {:server server
     :url (str "http://127.0.0.1:" (.getPort (.getAddress server)) "/jwks")}))

(defspec jwks-refreshes-to-the-current-key-set
  {:num-tests 5 :seed 424246}
  (prop/for-all [payload payload-gen]
    (let [old (jwk/generate :rsa {:size 2048 :kid "old" :alg :rs256})
          current (jwk/generate :rsa {:size 2048 :kid "current" :alg :rs256})
          body (atom (jwk/set->json (jwk/jwk-set [(jwk/public-jwk old)])))
          {:keys [server url]} (rotation-server body)]
      (try
        (let [source (jwks/remote-source url {:cache? false :retry? false})
              old-token (jws/sign old payload {:alg :rs256})]
          (is (= payload (:payload (jws/verify-with-jwks source old-token {:alg :rs256}))))
          (reset! body (jwk/set->json (jwk/jwk-set [(jwk/public-jwk current)])))
          (let [current-token (jws/sign current payload {:alg :rs256})]
            (and (= payload (:payload (jws/verify-with-jwks source current-token {:alg :rs256})))
                 (= :key-not-found
                    (:jose/error (ex-data (:throwable
                                           (thrown #(jws/verify-with-jwks
                                                     source old-token {:alg :rs256})))))))))
        (finally
          (.stop ^HttpServer server 0))))))
