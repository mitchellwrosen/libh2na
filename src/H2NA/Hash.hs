module H2NA.Hash
  ( hash
  , hashFold
  ) where

import Control.Foldl          (Fold(..))
import Crypto.Hash.Algorithms (Blake2b_256)
import Data.ByteString        (ByteString)

import qualified Crypto.Hash    as Hash
import qualified Data.ByteArray as ByteArray


-- | Hash bytes using the @Blake2b@ hash algorithm. Produces a 32-byte hash.
hash :: ByteString -> ByteString
hash =
  ByteArray.convert . Hash.hash @_ @Blake2b_256

-- | Hash a stream of bytes using the @Blake2b@ hash algorithm. Produces a
-- 32-byte hash.
hashFold :: Fold ByteString ByteString
hashFold =
  Fold
    Hash.hashUpdate
    (Hash.hashInit @Blake2b_256)
    (ByteArray.convert . Hash.hashFinalize)
