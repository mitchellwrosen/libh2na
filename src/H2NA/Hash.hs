{-# OPTIONS_GHC -fno-warn-incomplete-patterns #-}

module H2NA.Hash
  ( hash
  , hashFold
  , hashpw
  ) where

import H2NA.Salt (Salt, saltToByteString)

import Control.Foldl          (Fold(..))
import Crypto.Error           (CryptoFailable(..))
import Crypto.Hash.Algorithms (Blake2b_256)
import Data.ByteString        (ByteString)

import qualified Crypto.Hash       as Hash
import qualified Crypto.KDF.Argon2 as Argon2
import qualified Data.ByteArray    as ByteArray


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

-- | Hash a password to a 32-byte digest.
--
-- /Implementation/: @Argon2id@
hashpw :: Salt -> ByteString -> ByteString
hashpw salt password =
  case Argon2.hash options password (saltToByteString salt) 32 of
    CryptoPassed digest ->
      digest

  where
    options :: Argon2.Options
    options =
      Argon2.Options
        { Argon2.iterations = 1
        , Argon2.memory = 2 ^ (17 :: Int)
        , Argon2.parallelism = 4
        , Argon2.variant = Argon2.Argon2id
        , Argon2.version = Argon2.Version13
        }
