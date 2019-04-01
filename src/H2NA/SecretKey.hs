module H2NA.SecretKey
  ( SecretKey
  , generate
  , public
  ) where

import H2NA.Internal (PublicKey(..), SecretKey(..))

import Data.Coerce (coerce)

import qualified Crypto.PubKey.Curve25519 as Curve25519


generate :: IO SecretKey
generate =
  coerce @(IO Curve25519.SecretKey) Curve25519.generateSecretKey

public :: SecretKey -> PublicKey
public =
  coerce Curve25519.toPublic
