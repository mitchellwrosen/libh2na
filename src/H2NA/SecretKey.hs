module H2NA.SecretKey
  ( SecretKey
  , generateSecretKey
  , derivePublicKey
  ) where

import H2NA.Internal (PublicKey(..), SecretKey(..))

import Data.Coerce (coerce)

import qualified Crypto.PubKey.Curve25519 as Curve25519


-- | /Implementation/: @Curve25519@
generateSecretKey :: IO SecretKey
generateSecretKey =
  coerce @(IO Curve25519.SecretKey) Curve25519.generateSecretKey

derivePublicKey :: SecretKey -> PublicKey
derivePublicKey =
  coerce Curve25519.toPublic
