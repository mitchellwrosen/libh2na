{-# OPTIONS_GHC -fno-warn-incomplete-patterns #-}

module H2NA.Hash
  ( hash
  , hashFold
  ) where

import Control.Foldl          (Fold(..))
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
hashFold :: Fold ByteString ByteString
hashFold =
  Fold
    Hash.hashUpdate
    (Hash.hashInit @Blake2b_256)
    (ByteArray.convert . Hash.hashFinalize)
