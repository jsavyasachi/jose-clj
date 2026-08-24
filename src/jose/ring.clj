(ns jose.ring
  "Ring middleware for verifying Bearer JWT credentials.

  `wrap-bearer` adds verified claims to the request under `:claims` by
  default. It accepts either a verification JWK/key for `jose.jwt/verify` or
  a `jose.jwks` source for `jose.jwt/verify-with-jwks`."
  (:require [clojure.string :as str]
            [jose.jwt :as jwt])
  (:import (jose.jwks Source)))

(set! *warn-on-reflection* true)

(def ^:private default-unauthorized-response
  {:status 401
   :headers {"Content-Type" "text/plain; charset=utf-8"}
   :body "Unauthorized"})

(defn- authorization-header
  [request]
  (some (fn [[key value]]
          (when (and (string? key)
                     (= "authorization" (str/lower-case key)))
            value))
        (:headers request)))

(defn- bearer-token
  [request]
  (when-let [header (authorization-header request)]
    (second (and (string? header)
                 (re-matches #"(?i)^Bearer\s+([^\s]+)\s*$" header)))))

(defn- verify-token
  [verification-key token verify-opts]
  (if (instance? Source verification-key)
    (jwt/verify-with-jwks verification-key token verify-opts)
    (jwt/verify verification-key token verify-opts)))

(defn wrap-bearer
  "Wraps a Ring handler with Bearer JWT authentication.

  On valid credentials, verified claims are associated under `:claims` (or
  the keyword supplied as `:claims-key`) before the handler is called. The
  `:verify-opts` map is passed to `jose.jwt/verify` or
  `jose.jwt/verify-with-jwks`; it should include an algorithm allow-list.
  Missing or invalid credentials return `:unauthorized-response`, or call
  `:unauthorized-handler` with the request when supplied."
  ([handler verification-key]
   (wrap-bearer handler verification-key {}))
  ([handler verification-key opts]
   (let [claims-key (:claims-key opts :claims)
         verify-opts (:verify-opts opts {})
         unauthorized-handler (:unauthorized-handler opts)
         unauthorized-response (:unauthorized-response opts
                                                        default-unauthorized-response)
         unauthorized (or unauthorized-handler (constantly unauthorized-response))]
     (fn [request]
       (if-let [token (bearer-token request)]
         (if-let [claims (try
                           (verify-token verification-key token verify-opts)
                           (catch Exception _ nil))]
           (handler (assoc request claims-key claims))
           (unauthorized request))
         (unauthorized request))))))
