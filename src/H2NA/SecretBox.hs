{-# OPTIONS_GHC -fno-warn-incomplete-patterns #-}

-- | Secret-key cryptography suite.

module H2NA.SecretBox
  ( -- * Secret box API
    -- ** Encryption
    encrypt
  , encryptIO
  , encryptDetached
    -- ** Decryption
  , decrypt
  , decryptDetached
    -- ** Signing
  , sign
  , shortsign
    -- ** Nonce
  , Nonce
  , zeroNonce
  , generateNonce
    -- ** Signature
  , Signature(..)
  ) where

import H2NA.Internal (SecretKey(..))

import Control.Monad             (guard)
import Control.Monad.IO.Class
import Control.Monad.Trans.State
import Crypto.Error              (CryptoFailable(..))
import Data.Bits                 (unsafeShiftL, (.|.))
import Data.ByteArray            (Bytes)
import Data.ByteString           (ByteString)
import Data.Coerce               (coerce)
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
import qualified Crypto.Number.Serialize      as Number
import qualified Crypto.Random                as Random
import qualified Data.ByteArray               as ByteArray
import qualified Data.ByteArray.Encoding      as ByteArray.Encoding
import qualified Data.ByteArray.Hash          as ByteArray.Hash
import qualified Data.ByteString              as ByteString
import qualified Data.ByteString.Char8        as ByteString.Char8


-- | A nonce.
--
-- Given a initial nonce, you can generate an infinite list of related nonces
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
      case ChaCha.nonce12 (Number.i2ospOf_ 12 n :: Bytes) of
        CryptoPassed nonce' ->
          Nonce nonce'

  succ (Nonce nonce) =
    case Number.i2ospOf 12 (Number.os2ip nonce + 1) of
      Nothing ->
        zeroNonce
      Just (bytes :: Bytes) ->
        case ChaCha.nonce12 bytes of
          CryptoPassed nonce' ->
            Nonce nonce'

  toEnum n =
    case ChaCha.nonce12 (Number.i2ospOf_ 12 (fromIntegral n) :: Bytes) of
      CryptoPassed nonce ->
        Nonce nonce

-- | Base64-encoded nonce.
instance Show Nonce where
  show (Nonce nonce) =
    nonce
      & ByteArray.Encoding.convertToBase ByteArray.Encoding.Base64
      & ByteString.Char8.unpack

-- | The "zero" nonce.
--
-- This is only suitable for encrypting a message with a single-use secret key.
-- If you encrypt more than one message with a secret key, you must use a
-- different nonce each time.
zeroNonce :: Nonce
zeroNonce =
  case ChaCha.nonce12 (ByteString.replicate 12 0) of
    CryptoPassed nonce ->
      Nonce nonce

-- | Generate a random nonce.
generateNonce :: MonadIO m => m Nonce
generateNonce = liftIO $ do
  bytes :: Bytes <-
    Random.getRandomBytes 12

  case ChaCha.nonce12 bytes of
    CryptoPassed nonce ->
      pure (Nonce nonce)


-- | Encrypt and sign a message with a secret key and a nonce.
--
-- If the key is used more than once, then the nonce should be randomly
-- generated with 'generateNonce'. Otherwise, you may use 'zeroNonce'.
--
-- /Implementation/: @ChaCha20@, @HKDF@, @Poly1305@
encrypt ::
     SecretKey -- ^ Secret key
  -> Nonce -- ^ Nonce
  -> ByteString -- ^ Plaintext
  -> ByteString -- ^ Ciphertext
encrypt key (Nonce nonce) plaintext =
  let
    (ciphertext, signature) =
      evalState (encryptS nonce plaintext) (initializeChaCha key nonce)
  in
    ByteString.concat
      [ signature
      , ByteArray.convert nonce
      , ciphertext
      ]

-- | A variant of 'encrypt' that generates a random nonce with 'generateNonce'.
encryptIO ::
     MonadIO m
  => SecretKey -- ^ Secret key
  -> ByteString -- ^ Plaintext
  -> m ByteString -- ^ Ciphertext
encryptIO key plaintext = do
  nonce <- generateNonce
  pure (encrypt key nonce plaintext)

-- | A variant of 'encrypt' that does not combine the ciphertext with the
-- message signature.
--
-- This is necessary if you want to store the signature separately.
encryptDetached ::
     SecretKey -- ^ Secret key
  -> Nonce -- ^ Nonce
  -> ByteString -- ^ Plaintext
  -> (ByteString, Signature) -- ^ Ciphertext and signature
encryptDetached key (Nonce nonce) plaintext =
  let
    (ciphertext, signature) =
      evalState (encryptS nonce plaintext) (initializeChaCha key nonce)
  in
    (ByteArray.convert nonce <> ciphertext, Signature signature)

encryptS ::
     ChaCha.Nonce
  -> ByteString
  -> State ChaCha.State (ByteString, ByteString)
encryptS nonce plaintext = do
  modify' (ChaCha.appendAAD nonce)
  modify' ChaCha.finalizeAAD
  ciphertext <- state (ChaCha.encrypt plaintext)
  chacha <- get
  pure (ciphertext, ByteArray.convert (ChaCha.finalize chacha))

-- | Decrypt and verify a message with the secret key that was used to encrypt
-- and sign it.
--
-- /Implementation/: @ChaCha20@, @HKDF@, @Poly1305@
decrypt ::
     SecretKey -- ^ Secret key
  -> ByteString -- ^ Ciphertext
  -> Maybe ByteString -- ^ Plaintext
decrypt key payload0 =
  decryptDetached key payload1 (coerce signature)
  where
    (signature, payload1) =
      ByteString.splitAt 16 payload0


-- | Variant of 'decrypt' that is used to decrypt messages encrypted with
-- 'encryptDetached'.
decryptDetached ::
     SecretKey -- ^ Secret key
  -> ByteString -- ^ Ciphertext
  -> Signature -- ^ Signature
  -> Maybe ByteString -- ^ Plaintext
decryptDetached key payload1 (Signature signatureBytes) = do
  CryptoPassed signature <-
    Just (Poly1305.authTag signatureBytes)

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

  guard (signature == ChaCha.finalize chacha)

  pure plaintext

initializeChaCha :: SecretKey -> ChaCha.Nonce -> ChaCha.State
initializeChaCha (SecretKey key) nonce =
  case ChaCha.initialize (HKDF.extractSkip key) nonce of
    CryptoPassed chacha ->
      chacha


-- | A message signature with a constant-time 'Eq' instance.
newtype Signature
  = Signature { unSignature :: ByteString }

-- | Constant-time comparison.
instance Eq Signature where
  Signature x == Signature y =
    ByteArray.constEq x y

-- | Base64-encoded signature.
instance Show Signature where
  show (Signature sig) =
    sig
      & ByteArray.Encoding.convertToBase ByteArray.Encoding.Base64
      & ByteString.Char8.unpack


-- | Sign a message with a secret key, producing a 32-byte signature.
--
-- To verify the authenticity of a message was signed by a particular secret
-- key, simply re-sign the message and compare the signatures.
--
-- /Implementation/: @HKDF@, @HMAC-BLAKE2b-256@
sign ::
     SecretKey -- ^ Secret key
  -> ByteString -- ^ Message
  -> Signature -- ^ Signature
sign =
  coerce sign_

sign_ :: SecretKey -> ByteString -> ByteString
sign_ (SecretKey key) =
  ByteArray.convert . HMAC.hmac @_ @_ @Hash.Blake2b_256 (HKDF.extractSkip key)

-- | Sign a message with a secret key.
--
-- To verify the authenticity of a message was signed by a particular secret
-- key, simply re-sign the message and compare the signatures.
--
-- /Implementation/: @SipHash 2-4@
shortsign ::
     SecretKey -- ^ Secret key
  -> ByteString -- ^ Message
  -> Word64 -- ^ Signature
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
