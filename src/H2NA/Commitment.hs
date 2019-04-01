module H2NA.Commitment
  ( Commitment
  , commit
  , committed
  ) where

import Data.Bits       (shiftL, (.|.))
import Data.ByteString (ByteString)
import Data.Word       (Word8)

import qualified Data.ByteString as ByteString
import qualified Pedersen


-- | A cryptographic proof that some secret value was committed to.
--
-- The committer can choose to reveal the secret value later, and this
-- commitment is used to prove that the value was indeed used to produce it.
data Commitment
  = Commitment Pedersen.ECCommitParams Pedersen.ECCommitment Integer

-- | Commit to a secret value.
commit :: ByteString -> IO Commitment
commit value = do
  params :: Pedersen.ECCommitParams <-
    Pedersen.ecSetup Nothing

  Pedersen.ECPedersen commitment reveal_ <-
    Pedersen.ecCommit (byteStringToInteger value) params

  pure (Commitment params commitment (Pedersen.ecRevealScalar reveal_))

-- | Return whether the given value is equal to the one committed to.
committed :: Commitment -> ByteString -> Bool
committed (Commitment params commitment scalar) value =
  Pedersen.ecOpen
    params
    commitment
    Pedersen.ECReveal
      { Pedersen.ecRevealVal = byteStringToInteger value
      , Pedersen.ecRevealScalar = scalar
      }

byteStringToInteger :: ByteString -> Integer
byteStringToInteger =
  foldr step 0 . ByteString.unpack
  where
    step :: Word8 -> Integer -> Integer
    step n acc = acc `shiftL` 8 .|. fromIntegral n
