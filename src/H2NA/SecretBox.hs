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

import Control.Monad             (guard)
import Control.Monad.Trans.State
import Crypto.Error              (CryptoFailable(..))
import Data.ByteArray            (Bytes)
import Data.ByteString           (ByteString)
import Data.Function             ((&))

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
  evalState (encryptS nonce plaintext) (initialize key nonce)

encryptS :: ChaCha.Nonce -> Plaintext -> State ChaCha.State Ciphertext
encryptS nonce plaintext = do
  modify' (ChaCha.appendAAD nonce)
  modify' ChaCha.finalizeAAD
  ciphertext <- state (ChaCha.encrypt plaintext)
  chacha <- get
  pure
    (ByteString.concat
      [ ByteArray.convert (ChaCha.finalize chacha)
      , ByteArray.convert nonce
      , ciphertext
      ])

decrypt :: SecretKey -> Ciphertext -> Maybe Plaintext
decrypt key payload0 = do
  let
    (authBytes, payload1) =
      ByteString.splitAt 16 payload0

  CryptoPassed auth <-
    Just (Poly1305.authTag authBytes)

  let
    (nonceBytes, ciphertext) =
      ByteString.splitAt 12 payload1

  CryptoPassed nonce <-
    Just (ChaCha.nonce12 nonceBytes)

  let
    (plaintext, chacha) =
      initialize key nonce
        & ChaCha.appendAAD nonce
        & ChaCha.finalizeAAD
        & ChaCha.decrypt ciphertext

  guard (auth == ChaCha.finalize chacha)

  pure plaintext

initialize :: SecretKey -> ChaCha.Nonce -> ChaCha.State
initialize (SecretKey key) nonce =
  case ChaCha.initialize key nonce of
    CryptoPassed chacha ->
      chacha
