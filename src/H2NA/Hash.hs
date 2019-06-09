module H2NA.Hash
  ( hash
  , hashFold
  ) where

import Control.Foldl          (FoldM(..))
import Crypto.Hash.Algorithms (Blake2b_256)
import Data.ByteString        (ByteString)

import qualified Crypto.Hash    as Hash
import qualified Data.ByteArray as ByteArray


-- | Hash a message to a 32-byte digest.
--
-- /Implementation/: @BLAKE2b@
hash :: ByteString -> ByteString
hash =
  ByteArray.convert . Hash.hash @_ @Blake2b_256

-- | Hash a stream of messages to a 32-byte digest.
--
-- /Implementation/: @BLAKE2b@
hashFold :: Monad m => FoldM m ByteString ByteString
hashFold =
  FoldM
    (\a b -> pure (Hash.hashUpdate a b))
    (pure (Hash.hashInit @Blake2b_256))
    (pure . ByteArray.convert . Hash.hashFinalize)
