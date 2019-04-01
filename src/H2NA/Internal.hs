module H2NA.Internal where

import qualified Crypto.PubKey.Curve25519 as Curve25519


newtype PublicKey
  = PublicKey Curve25519.PublicKey

newtype SecretKey
  = SecretKey Curve25519.SecretKey
