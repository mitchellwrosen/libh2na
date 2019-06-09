module H2NA.Internal where

import qualified Crypto.PubKey.Curve25519 as Curve25519


-- | A 32-byte public key, derived from a secret key.
--
-- /Implementation/: @Curve25519@.
newtype PublicKey
  = PublicKey { unPublicKey :: Curve25519.PublicKey }

-- | A 32-byte secret key.
--
-- /Implementation/: @Curve25519@
newtype SecretKey
  = SecretKey { unSecretKey :: Curve25519.SecretKey }
