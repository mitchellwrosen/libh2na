module H2NA.Internal.KDF where

import H2NA.Internal (SecretKey(..))

import qualified Crypto.KDF.HKDF as HKDF


deriveKey :: SecretKey -> HKDF.PRK a
deriveKey (SecretKey key) =
  HKDF.extractSkip key
