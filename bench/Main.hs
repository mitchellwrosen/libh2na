module Main where

import Chronos.Bench
import Data.ByteString (ByteString)

import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Crypto.Random            as Random
import qualified Data.ByteArray           as ByteArray

main :: IO ()
main =
  defaultMain
    [ benchIO "random 32" (Random.getRandomBytes 32 :: IO ByteString)
    , benchIO "curve25519" Curve25519.generateSecretKey
    ]
