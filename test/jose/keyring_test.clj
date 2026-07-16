(ns jose.keyring-test
  (:require [clojure.test :refer [deftest is testing]]
            [jose.jwe :as jwe]
            [jose.jwk :as jwk]
            [jose.keyring :as keyring]
            [jose.jws :as jws])
  (:import (com.nimbusds.jose.jwk JWKSet)))

(deftest active-keys-issue-and-retained-keys-consume
  (let [sig-1 (jwk/generate :rsa {:kid "sig-1" :use :sig :alg :rs256})
        sig-2 (jwk/generate :rsa {:kid "sig-2" :use :sig :alg :rs256})
        enc-1 (jwk/generate :rsa {:kid "enc-1" :use :enc})
        enc-2 (jwk/generate :rsa {:kid "enc-2" :use :enc})
        original (keyring/key-ring [sig-1 enc-1]
                                   {:active-signing-kid "sig-1"
                                    :active-encryption-kid "enc-1"})
        old-jws (keyring/sign original "signed")
        old-jwe (keyring/encrypt original "encrypted")
        rotated (-> original
                    (keyring/rotate :signing sig-2 {:at 100})
                    (keyring/rotate :encryption enc-2 {:at 100}))
        new-jws (keyring/sign rotated "new signed")
        new-jwe (keyring/encrypt rotated "new encrypted")]
    (is (= "sig-1" (get-in (keyring/verify rotated old-jws {:algs #{:rs256}})
                             [:header :kid])))
    (is (= "encrypted" (:payload (keyring/decrypt rotated old-jwe))))
    (is (= "sig-2" (get-in (keyring/verify rotated new-jws {:algs #{:rs256}})
                             [:header :kid])))
    (is (= "new encrypted" (:payload (keyring/decrypt rotated new-jwe))))))

(deftest falls-back-when-kid-is-missing-or-wrong
  (let [old (jwk/generate :rsa {:kid "old"})
        active (jwk/generate :rsa {:kid "active"})
        ring (keyring/key-ring [old active]
                               {:active-signing-kid "active"
                                :active-encryption-kid "active"})
        missing-kid (jws/sign old "missing" {:kid nil})
        wrong-kid (jws/sign old "wrong" {:kid "active"})
        encrypted (jwe/encrypt old "secret" {:kid "active"})]
    (is (= "missing" (:payload (keyring/verify ring missing-kid {:algs #{:rs256}}))))
    (is (= "wrong" (:payload (keyring/verify ring wrong-kid {:algs #{:rs256}}))))
    (is (= "secret" (:payload (keyring/decrypt ring encrypted))))))

(deftest prune-applies-retention-policy
  (let [old (jwk/generate :rsa {:kid "old"})
        current (jwk/generate :rsa {:kid "current"})
        ring (-> (keyring/key-ring [old]
                                   {:active-signing-kid "old"
                                    :active-encryption-kid "old"})
                 (keyring/rotate :signing current {:at 100})
                 (keyring/rotate :encryption current {:at 100}))
        pruned (keyring/prune ring {:retention-seconds 50 :now 151})]
    (is (= #{"current"} (set (map jwk/key-id (.getKeys (keyring/public-jwks pruned))))))))

(deftest publishes-public-jwks-without-private-material
  (let [rsa (jwk/generate :rsa {:kid "rsa"})
        ec (jwk/generate :ec {:kid "ec"})
        symmetric (jwk/generate :oct {:kid "secret"})
        ring (keyring/key-ring [rsa ec symmetric]
                               {:active-signing-kid "rsa"
                                :active-encryption-kid "ec"})
        published (keyring/public-jwks ring)
        parsed-json (jwk/parse-set (keyring/public-jwks-json ring))]
    (is (instance? JWKSet published))
    (is (= #{"rsa" "ec"} (set (map jwk/key-id (.getKeys published)))))
    (is (every? (complement jwk/private?) (.getKeys published)))
    (is (= (jwk/set->maps published) (jwk/set->maps parsed-json)))))
