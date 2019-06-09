module H2NA.Internal.Signature where

import Data.ByteString (ByteString)
import Data.Coerce     (coerce)
import Data.Function   ((&))

import qualified Crypto.MAC.Poly1305     as Poly1305
import qualified Data.ByteArray          as ByteArray
import qualified Data.ByteArray.Encoding as ByteArray.Encoding
import qualified Data.ByteString.Char8   as ByteString.Char8


-- | A message signature with a constant-time 'Eq' instance.
newtype Signature
  = Signature { unSignature :: ByteString }

-- | Constant-time comparison.
instance Eq Signature where
  Signature x == Signature y =
    ByteArray.constEq x y


-- | Base64-encoded signature.
instance Show Signature where
  show (Signature sig) =
    sig
      & ByteArray.Encoding.convertToBase ByteArray.Encoding.Base64
      & ByteString.Char8.unpack

authToSignature :: Poly1305.Auth -> Signature
authToSignature =
  coerce (ByteArray.convert :: Poly1305.Auth -> ByteString)
