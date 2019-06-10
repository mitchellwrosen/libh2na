{-# OPTIONS_GHC -fno-warn-incomplete-patterns #-}

module H2NA.Internal.AEAD
  ( aeadEncrypt
  , aeadDecrypt
  , bytesToAuth
  , Nonce
  , nonceToBytes
  , bytesToNonce
  , generateNonce
  ) where

import H2NA.Internal.KDF                  (deriveKey)
import H2NA.Internal.PseudoRandomMaterial (PseudoRandomMaterial)

import Control.Monad.IO.Class
import Crypto.Error           (CryptoFailable(..))
import Data.ByteArray         (ByteArray, ByteArrayAccess, Bytes)
import Data.ByteString        (ByteString)
import Data.Coerce            (coerce)
import Data.Function          ((&))
import Data.Maybe             (fromJust)

import qualified Crypto.Cipher.ChaChaPoly1305 as ChaCha
import qualified Crypto.MAC.Poly1305          as Poly1305
import qualified Crypto.Number.Serialize      as Number
import qualified Crypto.Random                as Random
import qualified Data.ByteArray               as ByteArray
import qualified Data.ByteArray.Encoding      as ByteArray.Encoding
import qualified Data.ByteString              as ByteString
import qualified Data.ByteString.Char8        as ByteString.Char8


-- | A nonce.
--
-- Given a initial nonce, you can generate an infinite list of derived nonces
-- with the 'Enum' instance:
--
-- @
-- [ nonce .. ]
-- @
newtype Nonce
  = Nonce ChaCha.Nonce

instance Enum Nonce where
  fromEnum (Nonce nonce) =
    fromIntegral (Number.os2ip nonce)

  pred (Nonce nonce) =
    let
      n :: Integer
      n =
        case Number.os2ip nonce of
          0 ->
            79228162514264337593543950335 -- The maximum nonce, 12 bytes of 1s

          i ->
            i - 1
    in
      fromJust (bytesToNonce (Number.i2ospOf_ 12 n :: Bytes))

  succ (Nonce nonce) =
    case Number.i2ospOf 12 (Number.os2ip nonce + 1) of
      Nothing ->
        fromJust (bytesToNonce (ByteString.replicate 12 0))

      Just bytes ->
        fromJust (bytesToNonce (bytes :: Bytes))

  toEnum n =
    fromJust (bytesToNonce (Number.i2ospOf_ 12 (fromIntegral n) :: Bytes))

-- | Base64-encoded nonce.
instance Show Nonce where
  show (Nonce nonce) =
    nonce
      & ByteArray.Encoding.convertToBase ByteArray.Encoding.Base64
      & ByteString.Char8.unpack

nonceToBytes :: Nonce -> ByteString
nonceToBytes =
  coerce (ByteArray.convert :: ChaCha.Nonce -> ByteString)

bytesToNonce :: ByteArray bytes => bytes -> Maybe Nonce
bytesToNonce bytes =
  case ChaCha.nonce12 bytes of
    CryptoPassed nonce ->
      Just (Nonce nonce)
    _ ->
      Nothing

-- | Generate a random nonce.
generateNonce :: MonadIO m => m Nonce
generateNonce = liftIO $ do
  bytes :: Bytes <-
    Random.getRandomBytes 12

  pure (fromJust (bytesToNonce bytes))


aeadEncrypt ::
     ByteArrayAccess a
  => PseudoRandomMaterial a
  -> Nonce
  -> ByteString
  -> (ByteString, Poly1305.Auth)
aeadEncrypt key (Nonce nonce) plaintext =
  let
    state0 :: ChaCha.State
    state0 =
      case ChaCha.initialize (deriveKey key) nonce of
        CryptoPassed state ->
          state

    (ciphertext, state1) =
      ChaCha.encrypt plaintext state0
  in
    (ciphertext, ChaCha.finalize state1)

aeadDecrypt ::
     ByteArrayAccess a
  => PseudoRandomMaterial a
  -> Nonce
  -> ByteString
  -> (ByteString, Poly1305.Auth)
aeadDecrypt key (Nonce nonce) plaintext =
  let
    state0 :: ChaCha.State
    state0 =
      case ChaCha.initialize (deriveKey key) nonce of
        CryptoPassed state ->
          state

    (ciphertext, state1) =
      ChaCha.decrypt plaintext state0
  in
    (ciphertext, ChaCha.finalize state1)

bytesToAuth :: ByteString -> Maybe Poly1305.Auth
bytesToAuth bytes =
  case Poly1305.authTag bytes of
    CryptoPassed auth ->
      Just auth
    _ ->
      Nothing
