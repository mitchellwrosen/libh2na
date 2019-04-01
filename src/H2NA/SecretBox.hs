{-# OPTIONS_GHC -fno-warn-incomplete-patterns #-}

module H2NA.SecretBox
  ( encrypt
  , decrypt
  , sign
  , shortsign
  , Nonce
  , generateNonce
  , defaultNonce
  ) where

import H2NA.Internal (SecretKey(..))

import Control.Monad             (guard)
import Control.Monad.Trans.State
import Crypto.Error              (CryptoFailable(..))
import Data.Bits                 (unsafeShiftL, (.|.))
import Data.ByteArray            (Bytes)
import Data.ByteString           (ByteString)
import Data.Function             ((&))
import Data.Word                 (Word64, Word8)
import Foreign.Ptr               (plusPtr)
import Foreign.Storable          (peek)
import System.IO.Unsafe          (unsafeDupablePerformIO)

import qualified Crypto.Cipher.ChaChaPoly1305 as ChaCha
import qualified Crypto.Hash.Algorithms       as Hash
import qualified Crypto.KDF.HKDF              as HKDF
import qualified Crypto.MAC.HMAC              as HMAC
import qualified Crypto.MAC.Poly1305          as Poly1305
import qualified Crypto.Random                as Random
import qualified Data.ByteArray               as ByteArray
import qualified Data.ByteArray.Hash          as ByteArray.Hash
import qualified Data.ByteString              as ByteString


-- | A nonce.
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
--
-- /Implementation/: @ChaCha20@, @HKDF@, @Poly1305@
encrypt ::
     SecretKey
  -> Nonce
  -> ByteString -- ^ Plaintext
  -> ByteString -- ^ Ciphertext
encrypt key (Nonce nonce) plaintext =
  evalState (encryptS nonce plaintext) (initializeChaCha key nonce)

encryptS ::
     ChaCha.Nonce
  -> ByteString
  -> State ChaCha.State ByteString
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
--
-- /Implementation/: @ChaCha20@, @HKDF@, @Poly1305@
decrypt ::
     SecretKey
  -> ByteString -- ^ Ciphertext
  -> Maybe ByteString -- ^ Plaintext
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
  case ChaCha.initialize (HKDF.extractSkip key) nonce of
    CryptoPassed chacha ->
      chacha

-- | Sign a message with a secret key.
--
-- To verify the authenticity of a message was signed by a particular secret
-- key, simply re-sign the message and compare the signatures.
--
-- /Implementation/: @HKDF@, @HMAC-BLAKE2b-256@
sign ::
     SecretKey
  -> ByteString -- ^ Message
  -> ByteString -- ^ Signature
sign (SecretKey key) message =
  ByteArray.convert
    (HMAC.hmac (HKDF.extractSkip key) message :: HMAC.HMAC Hash.Blake2b_256)

-- | /Implementation/: @SipHash 2-4@
shortsign :: SecretKey -> ByteString -> Word64
shortsign key message =
  case ByteArray.Hash.sipHash (sipkey key) message of
    ByteArray.Hash.SipHash hash ->
      hash

sipkey :: SecretKey -> ByteArray.Hash.SipKey
sipkey (SecretKey key) =
  unsafeDupablePerformIO
    (ByteArray.withByteArray (HKDF.extractSkip key) $ \ptr -> do
      b0  :: Word8 <- peek ptr
      b1  :: Word8 <- peek (ptr `plusPtr` 1)
      b2  :: Word8 <- peek (ptr `plusPtr` 2)
      b3  :: Word8 <- peek (ptr `plusPtr` 3)
      b4  :: Word8 <- peek (ptr `plusPtr` 4)
      b5  :: Word8 <- peek (ptr `plusPtr` 5)
      b6  :: Word8 <- peek (ptr `plusPtr` 6)
      b7  :: Word8 <- peek (ptr `plusPtr` 7)
      b8  :: Word8 <- peek (ptr `plusPtr` 8)
      b9  :: Word8 <- peek (ptr `plusPtr` 9)
      b10 :: Word8 <- peek (ptr `plusPtr` 10)
      b11 :: Word8 <- peek (ptr `plusPtr` 11)
      b12 :: Word8 <- peek (ptr `plusPtr` 12)
      b13 :: Word8 <- peek (ptr `plusPtr` 13)
      b14 :: Word8 <- peek (ptr `plusPtr` 14)
      b15 :: Word8 <- peek (ptr `plusPtr` 15)

      let
        w0 :: Word64
        w0 =
          (fromIntegral b7  `unsafeShiftL` 56) .|.
          (fromIntegral b6  `unsafeShiftL` 48) .|.
          (fromIntegral b5  `unsafeShiftL` 40) .|.
          (fromIntegral b4  `unsafeShiftL` 32) .|.
          (fromIntegral b3  `unsafeShiftL` 24) .|.
          (fromIntegral b2  `unsafeShiftL` 16) .|.
          (fromIntegral b1  `unsafeShiftL`  8) .|.
           fromIntegral b0

      let
        w1 :: Word64
        w1 =
          (fromIntegral b15 `unsafeShiftL` 56) .|.
          (fromIntegral b14 `unsafeShiftL` 48) .|.
          (fromIntegral b13 `unsafeShiftL` 40) .|.
          (fromIntegral b12 `unsafeShiftL` 32) .|.
          (fromIntegral b11 `unsafeShiftL` 24) .|.
          (fromIntegral b10 `unsafeShiftL` 16) .|.
          (fromIntegral  b9 `unsafeShiftL`  8) .|.
           fromIntegral  b8

      pure (ByteArray.Hash.SipKey w0 w1))
