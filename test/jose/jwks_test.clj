(ns jose.jwks-test
  (:require [clojure.test :refer [deftest is testing]]
            [jose.jwk :as jwk]
            [jose.jwks :as jwks])
  (:import (clojure.lang ExceptionInfo)
           (com.sun.net.httpserver HttpHandler HttpServer)
           (java.net InetSocketAddress)
           (java.nio.charset StandardCharsets)))

(defn thrown-data
  [f]
  (try
    (f)
    nil
    (catch ExceptionInfo e
      (ex-data e))))

(defn test-server
  [respond]
  (let [server (HttpServer/create (InetSocketAddress. "127.0.0.1" 0) 0)]
    (.createContext server "/jwks"
                    (reify HttpHandler
                      (handle [_ exchange]
                        (let [[status body] (respond)
                              bytes (.getBytes (str body) StandardCharsets/UTF_8)]
                          (.sendResponseHeaders exchange status (count bytes))
                          (with-open [output (.getResponseBody exchange)]
                            (.write output bytes))))))
    (.start server)
    {:server server
     :url (str "http://127.0.0.1:"
               (.getPort (.getAddress server))
               "/jwks")}))

(deftest local-sources-select-keys
  (let [rsa-a (jwk/generate :rsa {:kid "a" :use :sig :alg :rs256})
        rsa-b (jwk/generate :rsa {:kid "b" :use :enc})
        oct-c (jwk/generate :oct {:kid "c" :use :sig})
        source (jwks/local-source [rsa-a rsa-b oct-c])]
    (testing "no matcher fields returns all keys"
      (is (= ["a" "b" "c"] (mapv jwk/key-id (jwks/get-keys source {})))))
    (testing "filters by kid"
      (is (= ["a"] (mapv jwk/key-id (jwks/get-keys source {:kid "a"})))))
    (testing "filters by key type"
      (is (= ["a" "b"] (mapv jwk/key-id (jwks/get-keys source {:kty :rsa})))))
    (testing "filters by key use"
      (is (= ["a" "c"] (mapv jwk/key-id (jwks/get-keys source {:use :sig})))))
    (testing "filters by algorithm"
      (is (= ["a"] (mapv jwk/key-id (jwks/get-keys source {:alg :rs256})))))
    (testing "empty vector on no match"
      (is (= [] (jwks/get-keys source {:kid "missing"}))))
    (testing "find-key returns one matching key"
      (is (= "a" (jwk/key-id (jwks/find-key source "a"))))
      (is (nil? (jwks/find-key source "missing"))))))

(deftest local-sources-support-full-jwk-matching
  (let [rsa-private (jwk/generate :rsa {:kid "rsa-private"
                                        :use :sig
                                        :key-ops [:sign :verify]
                                        :x5t "AQID"
                                        :x5t#S256 "BAUG"})
        rsa-public (jwk/public-jwk (jwk/generate :rsa {:kid "rsa-public"}))
        ec-private (jwk/generate :ec {:kid "ec-private" :curve :p-256})
        source (jwks/local-source [rsa-private rsa-public ec-private])]
    (testing "filters by key operations"
      (is (= ["rsa-private"]
             (mapv jwk/key-id
                   (jwks/get-keys source {:key-ops [:sign :verify]})))))
    (testing "filters by curves"
      (is (= ["ec-private"]
             (mapv jwk/key-id (jwks/get-keys source {:curves [:p-256]})))))
    (testing "filters by exact and bounded key sizes"
      (is (= ["ec-private"]
             (mapv jwk/key-id (jwks/get-keys source {:key-size 256 :kty :ec}))))
      (is (= #{"rsa-private" "rsa-public"}
             (set (map jwk/key-id
                       (jwks/get-keys source {:min-key-size 2048
                                              :max-key-size 2048}))))))
    (testing "filters public and private keys"
      (is (= ["rsa-public"]
             (mapv jwk/key-id (jwks/get-keys source {:private? false}))))
      (is (= #{"rsa-private" "ec-private"}
             (set (map jwk/key-id (jwks/get-keys source {:private? true}))))))
    (testing "filters X.509 thumbprints"
      (is (= ["rsa-private"]
             (mapv jwk/key-id (jwks/get-keys source {:x5t "AQID"}))))
      (is (= ["rsa-private"]
             (mapv jwk/key-id (jwks/get-keys source {:x5t#S256 "BAUG"})))))))

(deftest remote-source-rejects-invalid-url
  (is (= :invalid-url
         (:jose/error (thrown-data #(jwks/remote-source "not a url"))))))

(deftest remote-source-retries-and-reports-health-events
  (let [requests (atom 0)
        health-reports (atom [])
        cache-events (atom [])
        json (jwk/set->json (jwk/jwk-set [(jwk/generate :rsa {:kid "remote"})]))
        {:keys [server url]} (test-server #(if (= 1 (swap! requests inc))
                                            [500 "unavailable"]
                                            [200 json]))]
    (try
      (let [source (jwks/remote-source url {:retry? true
                                            :cache-event-listener
                                            #(swap! cache-events conj %)
                                            :health-report-listener
                                            #(swap! health-reports conj %)})]
        (is (= ["remote"] (mapv jwk/key-id (jwks/get-keys source {}))))
        (is (= 2 @requests))
        (is (seq @cache-events))
        (is (seq @health-reports)))
      (finally
        (.stop server 0)))))

(deftest remote-source-fails-over-to-another-source
  (let [fallback (jwks/local-source [(jwk/generate :rsa {:kid "fallback"})])
        {:keys [server url]} (test-server (constantly [500 "unavailable"]))]
    (try
      (let [source (jwks/remote-source url {:retry? false :failover fallback})]
        (is (= ["fallback"] (mapv jwk/key-id (jwks/get-keys source {})))))
      (finally
        (.stop server 0)))))

(deftest remote-source-serves-stale-keys-during-outage
  (let [available? (atom true)
        json (jwk/set->json (jwk/jwk-set [(jwk/generate :rsa {:kid "stale"})]))
        {:keys [server url]} (test-server #(if @available?
                                            [200 json]
                                            [500 "unavailable"]))]
    (try
      (let [source (jwks/remote-source url {:cache-ttl-ms 20
                                            :cache-refresh-ms 10
                                            :refresh-ahead? false
                                            :rate-limit? false
                                            :retry? false
                                            :outage-ttl-ms 1000})]
        (is (= ["stale"] (mapv jwk/key-id (jwks/get-keys source {}))))
        (reset! available? false)
        (Thread/sleep 30)
        (is (= ["stale"] (mapv jwk/key-id (jwks/get-keys source {})))))
      (finally
        (.stop server 0)))))

(deftest remote-source-accepts-cache-and-resilience-modes
  (is (jwks/remote-source "https://example.test/jwks"
                          {:cache? false
                           :retry? false
                           :outage-tolerant? false}))
  (is (jwks/remote-source "https://example.test/jwks"
                          {:cache-forever? true
                           :rate-limit-ms 1000
                           :retry? true}))
  (is (jwks/remote-source "https://example.test/jwks"
                          {:outage-forever? true}))
  (is (jwks/remote-source "https://example.test/jwks"
                          {:cache-ttl-ms 60000
                           :cache-refresh-ms 1000
                           :refresh-ahead-ms 10000
                           :refresh-ahead-scheduled? false
                           :rate-limit-ms 1000
                           :outage-ttl-ms 120000})))

(deftest ^:integration google-jwks-has-rsa-keys
  (let [source (jwks/remote-source "https://www.googleapis.com/oauth2/v3/certs")]
    (is (pos? (count (jwks/get-keys source {:kty :rsa}))))))
