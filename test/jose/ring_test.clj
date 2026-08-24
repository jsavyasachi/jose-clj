(ns jose.ring-test
  (:require [clojure.test :refer [deftest is testing]]
            [jose.jwk :as jwk]
            [jose.jwks :as jwks]
            [jose.jwt :as jwt]
            [jose.ring :as ring]))

(deftest bearer-middleware-verifies-and-attaches-claims
  (let [key (jwk/generate :oct {:size 256})
        token (jwt/sign key {:sub "alice"} {:alg :hs256})
        handler (fn [request] {:status 200 :body (:sub (:claims request))})
        wrapped (ring/wrap-bearer handler key {:verify-opts {:algs #{:hs256}}})]
    (is (= {:status 200 :body "alice"}
           (wrapped {:headers {"authorization" (str "Bearer " token)}})))))

(deftest bearer-middleware-supports-jwks-sources
  (let [key (jwk/generate :rsa {:kid "signing" :alg :rs256})
        source (jwks/local-source [(jwk/public-jwk key)])
        token (jwt/sign key {:sub "alice"} {:alg :rs256})
        wrapped (ring/wrap-bearer identity source {:verify-opts {:algs #{:rs256}}})]
    (is (= {:sub "alice"}
           (:claims (wrapped {:headers {"Authorization" (str "Bearer " token)}}))))))

(deftest bearer-middleware-uses-configurable-unauthorized-handler
  (let [requests (atom [])
        handler (fn [request]
                  (swap! requests conj request)
                  {:status 401 :body "custom"})
        wrapped (ring/wrap-bearer identity (jwk/generate :oct {:size 256})
                                   {:verify-opts {:algs #{:hs256}}
                                    :unauthorized-handler handler})]
    (testing "missing credentials"
      (let [request {:uri "/private"}]
        (is (= {:status 401 :body "custom"} (wrapped request)))
        (is (= [request] @requests))))
    (testing "invalid credentials"
      (is (= {:status 401 :body "custom"}
             (wrapped {:headers {"Authorization" "Bearer invalid"}})))
      (is (= 2 (count @requests))))))

(deftest bearer-middleware-returns-default-unauthorized-response
  (let [wrapped (ring/wrap-bearer identity (jwk/generate :oct {:size 256})
                                   {:verify-opts {:algs #{:hs256}}})]
    (is (= {:status 401
            :headers {"Content-Type" "text/plain; charset=utf-8"}
            :body "Unauthorized"}
           (wrapped {})))))
