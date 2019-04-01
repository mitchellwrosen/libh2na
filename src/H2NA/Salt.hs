module H2NA.Salt
  ( Salt
  , saltToByteString
  , generateSalt
  ) where

import Crypto.Random   (getRandomBytes)
import Data.ByteString (ByteString)
import Data.Coerce     (coerce)


newtype Salt
  = Salt ByteString

saltToByteString :: Salt -> ByteString
saltToByteString (Salt salt) =
  salt

-- | Generate a 16-byte salt.
generateSalt :: IO Salt
generateSalt =
  coerce (getRandomBytes 16 :: IO ByteString)
