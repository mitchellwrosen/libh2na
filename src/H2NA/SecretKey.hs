module H2NA.SecretKey
  ( SecretKey
  , generateSecretKey
  , derivePublicKey
  ) where

import H2NA.Internal (PublicKey(..), SecretKey(..))

import Control.Monad.IO.Class
import Data.Coerce            (coerce)

import qualified Crypto.PubKey.Curve25519 as Curve25519


-- | Generate a secret key.
--
-- A secret key must never be disclosed.
generateSecretKey :: MonadIO m => m SecretKey
generateSecretKey =
  liftIO (coerce @(IO Curve25519.SecretKey) Curve25519.generateSecretKey)

-- | Derive a public key from a secret one.
--
-- A public key may be disclosed to anyone.
derivePublicKey :: SecretKey -> PublicKey
derivePublicKey =
  coerce Curve25519.toPublic
