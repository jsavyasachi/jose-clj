(ns jose.pem-test
  (:require [clojure.test :refer [deftest is testing]]
            [jose.jwk :as jwk]
            [jose.pem :as pem])
  (:import (clojure.lang ExceptionInfo)
           (java.security KeyPairGenerator)
           (java.security.spec ECGenParameterSpec)
           (java.util Base64)))

(def certificate-pem
  (str "-----BEGIN CERTIFICATE-----\n"
       "MIIDETCCAfmgAwIBAgIUDnur11Sa01vejxQkvfb2nIdc+C4wDQYJKoZIhvcNAQEL\n"
       "BQAwGDEWMBQGA1UEAwwNam9zZS1jbGotdGVzdDAeFw0yNjA3MTEwNDQwMzlaFw0y\n"
       "NjA3MTIwNDQwMzlaMBgxFjAUBgNVBAMMDWpvc2UtY2xqLXRlc3QwggEiMA0GCSqG\n"
       "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDp6Ng3iH0ulCml2+LI2j2HUmPQC7hqBKd+\n"
       "5/gi8gdSBabwQ2Py+UcTyUg1xpPL0dSazUIlFa6GPg3RGq1AjB1ekV6Xa8mzY62S\n"
       "+BeBxKgAtwOTu4DWkPowBBk39FVd/oPF0zovs2lrrTDhNh41dwTu8px4HQ8X7n87\n"
       "g7c7LQ9LCBAfrTROr4q3a1OhqlPJPZk3bPYZ3Wfgtz5KeZ+L0Y0s6v+IQITYH0ib\n"
       "IL4cOqFKXcs/qQaBAcN3G/gnYylGfVWIKjsD8J0+gu7lHu3lehLuIxWjxDTvdNyi\n"
       "TkopAWHOlceVdVW/RlQPYg9AlFT61tYF9PL47c/qtZ4HiWDbzPqBAgMBAAGjUzBR\n"
       "MB0GA1UdDgQWBBQNk+tN6RIqmeMyqRTepv0jLc/axDAfBgNVHSMEGDAWgBQNk+tN\n"
       "6RIqmeMyqRTepv0jLc/axDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA\n"
       "A4IBAQB5IlHAVUAGJup+bNhbiluRCB0tStCHgA/E6EzjnnwC9VkftvEohOy9SR05\n"
       "tZ/IHdfEYUC56yPWuMjDzEaGdmYkZhgBJORFa0SMd+BcTt7DiEQ+HTgnpzrgJCle\n"
       "bmG5qQXJvGU3q1vK65SaGuEigr9sOYvJ7vtkYVcE8ptic6khfc+dzOrLAn06zNGd\n"
       "tRKDzQ4wbvc4mqfnt3YZzNuKrBSMMfRTWOUqfNSlt6CfbZB+hkypx7WFAxM7L8Ap\n"
       "vgOLRqKTv/bQ9FDXVdGVoQF7EkUeperei5w6i1dTvbzqXfzNzQTYSz/BiloWXvmo\n"
       "nOknsCuMecltPn/1fQ/5E4G7UaXy\n"
       "-----END CERTIFICATE-----\n"))

(defn thrown-data
  [f]
  (try
    (f)
    nil
    (catch ExceptionInfo e
      (ex-data e))))

(defn pem-block
  [label bytes]
  (let [encoded (.encodeToString (Base64/getEncoder) bytes)]
    (str "-----BEGIN " label "-----\n"
         (apply str (map #(str (apply str %) "\n") (partition-all 64 encoded)))
         "-----END " label "-----\n")))

(defn generated-keypair
  [kind]
  (let [generator (KeyPairGenerator/getInstance kind)]
    (case kind
      "RSA" (.initialize generator 2048)
      "EC" (.initialize generator (ECGenParameterSpec. "secp256r1")))
    (.generateKeyPair generator)))

(deftest generated-jwk-round-trips-through-pem
  (doseq [[label key] [[:rsa (jwk/generate :rsa {:size 2048})]
                       [:ec (jwk/generate :ec {:curve :p-256})]]]
    (testing label
      (let [private-pem (pem/jwk->pem key {:private? true})
            public-pem (pem/jwk->pem key)
            private-jwk (pem/pem->jwk private-pem)
            public-jwk (pem/pem->jwk public-pem)]
        (is (= (jwk/thumbprint key) (jwk/thumbprint private-jwk)))
        (is (= (jwk/thumbprint (jwk/public-jwk key)) (jwk/thumbprint public-jwk)))
        (is (jwk/private? private-jwk))
        (is (not (jwk/private? public-jwk)))
        (is (.endsWith ^String private-pem "\n"))
        (is (.endsWith ^String public-pem "\n"))))))

(deftest parses-java-generated-public-and-private-pem
  (doseq [[label keypair] [[:rsa (generated-keypair "RSA")]
                           [:ec (generated-keypair "EC")]]]
    (testing label
      (let [public-pem (pem-block "PUBLIC KEY" (.getEncoded (.getPublic keypair)))
            private-pem (str public-pem
                             (pem-block "PRIVATE KEY" (.getEncoded (.getPrivate keypair))))]
        (is (= label (jwk/key-type (pem/pem->jwk public-pem))))
        (is (= label (jwk/key-type (pem/pem->jwk private-pem))))
        (is (jwk/private? (pem/pem->jwk private-pem)))))))

(deftest parses-x509-certificate-pem
  (let [parsed (pem/pem->jwk certificate-pem)]
    (is (= :rsa (jwk/key-type parsed)))
    (is (not (jwk/private? parsed)))))

(deftest pem-failures-are-ex-info
  (is (= :invalid-option
         (:jose/error (thrown-data #(pem/jwk->pem (jwk/generate :oct {:size 256}))))))
  (is (= :invalid-option
         (:jose/error (thrown-data #(pem/jwk->pem (jwk/public-jwk (jwk/generate :rsa {:size 2048}))
                                                  {:private? true})))))
  (is (= :parse-failure
         (:jose/error (thrown-data #(pem/pem->jwk "not pem"))))))
