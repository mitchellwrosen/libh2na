module H2NA.SecretKey
  ( SecretKey
  , generateSecretKey
  , derivePublicKey
    -- ** Conversion
  , secretKeyToBytes
  , bytesToSecretKey
  ) where

import H2NA.Internal (PublicKey(..), SecretKey(..))

import Control.Monad.IO.Class
import Crypto.Error           (CryptoFailable(..))
import Data.ByteString        (ByteString)
import Data.Coerce            (coerce)

import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Data.ByteArray           as ByteArray


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


-- | View a secret key as 32-byte string.
secretKeyToBytes :: SecretKey -> ByteString
secretKeyToBytes =
  ByteArray.convert . unSecretKey

-- | Read a secret key from a 32-byte string.
bytesToSecretKey :: ByteString -> Maybe SecretKey
bytesToSecretKey bytes =
  case Curve25519.secretKey bytes of
    CryptoPassed key ->
      Just (SecretKey key)
    _ ->
      Nothing

