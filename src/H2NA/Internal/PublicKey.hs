module H2NA.Internal.PublicKey
  ( PublicKey(..)
  , publicKeyToBytes
  , bytesToPublicKey
  ) where

import H2NA.Internal.Encoding (encodeBase64)

import Control.DeepSeq (NFData)
import Crypto.Error    (CryptoFailable(..))
import Data.ByteString (ByteString)
import Data.Coerce     (coerce)

import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Data.ByteArray           as ByteArray
import qualified Data.ByteString.Char8    as ByteString.Char8


-- | A 32-byte public key, derived from a secret key.
--
-- /Implementation/: @Curve25519@.
newtype PublicKey
  = PublicKey { unPublicKey :: Curve25519.PublicKey }
  deriving newtype (Eq, NFData)

-- | Base64-encoded public key.
instance Show PublicKey where
  show =
    ByteString.Char8.unpack . encodeBase64 . publicKeyToBytes

-- | View a public key as 32-byte string.
publicKeyToBytes ::
     PublicKey -- ^
  -> ByteString
publicKeyToBytes =
  coerce (ByteArray.convert :: Curve25519.PublicKey -> ByteString)

-- | Read a public key from a 32-byte string.
bytesToPublicKey ::
     ByteString -- ^
  -> Maybe PublicKey
bytesToPublicKey bytes =
  case Curve25519.publicKey bytes of
    CryptoPassed key ->
      Just (coerce key)
    _ ->
      Nothing
