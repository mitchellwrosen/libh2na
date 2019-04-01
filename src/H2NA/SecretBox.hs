{-# OPTIONS_GHC -fno-warn-incomplete-patterns #-}

module H2NA.SecretBox
  ( encrypt
  , decrypt
  , sign
  , SecretKey
  , generateSecretKey
  , Nonce
  , generateNonce
  , defaultNonce
  , Plaintext
  , Ciphertext
  , Signature
  ) where

import Control.Monad             (guard)
import Control.Monad.Trans.State
import Crypto.Error              (CryptoFailable(..))
import Data.ByteArray            (Bytes)
import Data.ByteString           (ByteString)
import Data.Function             ((&))

import qualified Crypto.Cipher.ChaChaPoly1305 as ChaCha
import qualified Crypto.Hash.Algorithms       as Hash
import qualified Crypto.MAC.HMAC              as HMAC
import qualified Crypto.MAC.Poly1305          as Poly1305
import qualified Crypto.Random                as Random
import qualified Data.ByteArray               as ByteArray
import qualified Data.ByteString              as ByteString


type Plaintext
  = ByteString

type Ciphertext
  = ByteString

type Signature
  = ByteString

newtype SecretKey
  = SecretKey Bytes

-- | Generate a random secret key.
generateSecretKey :: IO SecretKey
generateSecretKey =
  SecretKey <$>
    Random.getRandomBytes 32

newtype Nonce
  = Nonce ChaCha.Nonce

-- | Generate a random nonce.
generateNonce :: IO Nonce
generateNonce = do
  bytes :: Bytes <-
    Random.getRandomBytes 12

  case ChaCha.nonce12 bytes of
    CryptoPassed nonce ->
      pure (Nonce nonce)

-- | The default nonce.
defaultNonce :: Nonce
defaultNonce =
  case ChaCha.nonce12 (ByteString.replicate 12 0) of
    CryptoPassed nonce ->
      Nonce nonce

-- | Encrypt and sign a message with a secret key and a nonce.
--
-- If the key is used more than once, then the nonce should be randomly
-- generated with 'generateNonce'. Otherwise, you may use 'defaultNonce'.
encrypt :: SecretKey -> Nonce -> Plaintext -> Ciphertext
encrypt key (Nonce nonce) plaintext =
  evalState (encryptS nonce plaintext) (initializeChaCha key nonce)

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

-- | Decrypt and verify a message with the secret key that was used to encrypt
-- and sign it.
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
      initializeChaCha key nonce
        & ChaCha.appendAAD nonce
        & ChaCha.finalizeAAD
        & ChaCha.decrypt ciphertext

  guard (auth == ChaCha.finalize chacha)

  pure plaintext

initializeChaCha :: SecretKey -> ChaCha.Nonce -> ChaCha.State
initializeChaCha (SecretKey key) nonce =
  case ChaCha.initialize key nonce of
    CryptoPassed chacha ->
      chacha

-- | Sign a message with a secret key.
--
-- To verify that a message was signed by a particular secret key, given the
-- message and a signature, simply re-sign the message and compare the
-- signatures.
sign :: SecretKey -> ByteString -> Signature
sign (SecretKey key) message =
  ByteArray.convert (HMAC.hmac key message :: HMAC.HMAC Hash.Blake2sp_256)
