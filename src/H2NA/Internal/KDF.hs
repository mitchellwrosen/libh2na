module H2NA.Internal.KDF where

import H2NA.Internal.PseudoRandomMaterial (PseudoRandomMaterial(..))

import Data.ByteArray (ByteArrayAccess)

import qualified Crypto.KDF.HKDF as HKDF


deriveKey :: ByteArrayAccess a => PseudoRandomMaterial a -> HKDF.PRK a
deriveKey (PseudoRandomMaterial key) =
  HKDF.extractSkip key
