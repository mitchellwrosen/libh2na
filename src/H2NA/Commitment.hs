module H2NA.Commitment
  ( Commitment
  , commit
  , committed
  ) where

import Crypto.Hash.Algorithms (Blake2s_256)
import Crypto.Number.Serialize (os2ip)
import Data.ByteString         (ByteString)

import qualified Crypto.Hash as Hash
import qualified Pedersen


-- | A cryptographic proof that some secret value was committed to.
--
-- The committer can choose to reveal the secret value later, and this
-- commitment is used to prove that the value was indeed used to produce it.
data Commitment
  = Commitment Pedersen.ECCommitParams Pedersen.ECCommitment Integer

-- | Commit to a secret value.
--
-- This function internally hashes the secret value first, so it may be
-- arbitrarily long.
commit :: ByteString -> IO Commitment
commit value = do
  params :: Pedersen.ECCommitParams <-
    Pedersen.ecSetup Nothing

  Pedersen.ECPedersen commitment reveal_ <-
    Pedersen.ecCommit (hash value) params

  pure (Commitment params commitment (Pedersen.ecRevealScalar reveal_))

-- | Return whether the given value is equal to the one committed to.
committed :: Commitment -> ByteString -> Bool
committed (Commitment params commitment scalar) value =
  Pedersen.ecOpen
    params
    commitment
    Pedersen.ECReveal
      { Pedersen.ecRevealVal = hash value
      , Pedersen.ecRevealScalar = scalar
      }

hash :: ByteString -> Integer
hash =
  os2ip . Hash.hash @_ @Blake2s_256
