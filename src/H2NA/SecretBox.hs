{-# OPTIONS_GHC -fno-warn-incomplete-patterns #-}

module H2NA.SecretBox
  ( encrypt
  , decrypt
  , SecretKey
  , generateSecretKey
  , Nonce
  , generateNonce
  , Plaintext
  , Ciphertext
  ) where

import Control.Monad   (guard)
import Crypto.Error    (CryptoFailable(..))
import Data.ByteArray  (Bytes)
import Data.ByteString (ByteString)

import qualified Crypto.Cipher.ChaChaPoly1305 as ChaCha
import qualified Crypto.MAC.Poly1305          as Poly1305
import qualified Crypto.Random                as Random
import qualified Data.ByteArray               as ByteArray
import qualified Data.ByteString              as ByteString


type Plaintext
  = ByteString

type Ciphertext
  = ByteString

newtype SecretKey
  = SecretKey Bytes

generateSecretKey :: IO SecretKey
generateSecretKey =
  SecretKey <$>
    Random.getRandomBytes 32

newtype Nonce
  = Nonce ChaCha.Nonce

generateNonce :: IO Nonce
generateNonce = do
  bytes :: Bytes <-
    Random.getRandomBytes 12

  case ChaCha.nonce12 bytes of
    CryptoPassed nonce ->
      pure (Nonce nonce)

encrypt :: SecretKey -> Nonce -> Plaintext -> Ciphertext
encrypt key (Nonce nonce) plaintext =
  ByteArray.convert auth <> ciphertext

  where
    (ciphertext, state) =
      ChaCha.encrypt plaintext (initialize key nonce)

    auth :: Poly1305.Auth
    auth =
      ChaCha.finalize state

decrypt :: SecretKey -> Nonce -> Ciphertext -> Maybe Plaintext
decrypt key (Nonce nonce) payload = do
  let
    (authBytes, ciphertext) =
      ByteString.splitAt 16 payload

  CryptoPassed auth <-
    Just (Poly1305.authTag authBytes)

  let
    (plaintext, state) =
      ChaCha.decrypt ciphertext (initialize key nonce)

  guard (auth == ChaCha.finalize state)

  pure plaintext

initialize :: SecretKey -> ChaCha.Nonce -> ChaCha.State
initialize (SecretKey key) nonce =
  case ChaCha.initialize key nonce of
    CryptoPassed state ->
      state
