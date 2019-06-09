module H2NA.PublicKey
  ( PublicKey
    -- ** Conversion
  , publicKeyToBytes
  , bytesToPublicKey
  ) where

import H2NA.Internal (PublicKey(..))

import Crypto.Error    (CryptoFailable(..))
import Data.ByteString (ByteString)
import Data.Coerce     (coerce)

import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Data.ByteArray           as ByteArray


-- | View a public key as 32-byte string.
publicKeyToBytes :: PublicKey -> ByteString
publicKeyToBytes =
  coerce (ByteArray.convert :: Curve25519.PublicKey -> ByteString)

-- | Read a public key from a 32-byte string.
bytesToPublicKey :: ByteString -> Maybe PublicKey
bytesToPublicKey bytes =
  case Curve25519.publicKey bytes of
    CryptoPassed key ->
      Just (coerce key)
    _ ->
      Nothing
