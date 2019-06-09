{-# OPTIONS_GHC -fno-warn-incomplete-patterns #-}

-- | Secret-key cryptography suite.

module H2NA.SecretBox
  ( -- * Secret box API
    -- ** Encryption
    encrypt
  , encryptIO
  , encryptDetached
  , encryptSequence
  , encryptSequenceIO
    -- ** Decryption
  , decrypt
  , decryptDetached
  , decryptSequence
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

import H2NA.Internal           (SecretKey(..))
import H2NA.Internal.AEAD
import H2NA.Internal.KDF       (deriveKey)
import H2NA.Internal.Signature

import Control.Applicative       (empty, (<|>))
import Control.Monad             (guard)
import Control.Monad.IO.Class
import Control.Monad.Trans.Class
import Control.Monad.Trans.Maybe
import Data.Bits                 (unsafeShiftL, (.|.))
import Data.ByteString           (ByteString)
import Data.Coerce               (coerce)
import Data.Word                 (Word64, Word8)
import Foreign.Ptr               (plusPtr)
import Foreign.Storable          (peek)
import List.Transformer          (ListT)
import System.IO.Unsafe          (unsafeDupablePerformIO)

import qualified Crypto.Hash.Algorithms as Hash
import qualified Crypto.MAC.HMAC        as HMAC
import qualified Crypto.MAC.Poly1305    as Poly1305
import qualified Data.ByteArray         as ByteArray
import qualified Data.ByteArray.Hash    as ByteArray.Hash
import qualified Data.ByteString        as ByteString
import qualified List.Transformer       as ListT


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
encrypt key nonce plaintext =
  let
    (ciphertext, auth) =
      aeadEncrypt key nonce plaintext
  in
    ByteString.concat
      [ coerce (authToSignature auth)
      , nonceToBytes nonce
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
-- This is useful if you want to store the signature separately.
encryptDetached ::
     SecretKey -- ^ Secret key
  -> Nonce -- ^ Nonce
  -> ByteString -- ^ Plaintext
  -> (ByteString, Signature) -- ^ Ciphertext and signature
encryptDetached key nonce plaintext =
  let
    (ciphertext, auth) =
      aeadEncrypt key nonce plaintext
  in
    (nonceToBytes nonce <> ciphertext, authToSignature auth)

-- | A variant of 'encrypt' suitable for encrypting a sequence of messages.
encryptSequence ::
     forall m.
     Monad m
  => SecretKey -- ^ SecretKey
  -> Nonce -- ^ Nonce
  -> ListT m ByteString -- ^ Plaintext sequence
  -> ListT m ByteString -- ^ Ciphertext sequence
encryptSequence key nonce0 plaintext0 =
  pure (nonceToBytes nonce0) <|> ListT.unfold step (nonce0, plaintext0)

  where
    step ::
         (Nonce, ListT m ByteString)
      -> m (Maybe (ByteString, (Nonce, ListT m ByteString)))
    step (nonce, plaintext) =
      ListT.next plaintext >>= \case
        ListT.Nil ->
          pure Nothing

        ListT.Cons x xs ->
          let
            (ciphertext, auth) =
              aeadEncrypt key nonce x
          in
            pure (Just (coerce (authToSignature auth) <> ciphertext, (succ nonce, xs)))

-- | A variant of 'encryptSequence' that generates a random nonce with
-- 'generateNonce'.
encryptSequenceIO ::
     MonadIO m
  => SecretKey -- ^ SecretKey
  -> ListT m ByteString -- ^ Plaintext sequence
  -> ListT m ByteString -- ^ Ciphertext sequence
encryptSequenceIO key plaintext = do
  nonce <- liftIO generateNonce
  encryptSequence key nonce plaintext

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


-- | A variant of 'decrypt' that is used to decrypt messages encrypted with
-- 'encryptDetached'.
decryptDetached ::
     SecretKey -- ^ Secret key
  -> ByteString -- ^ Ciphertext
  -> Signature -- ^ Signature
  -> Maybe ByteString -- ^ Plaintext
decryptDetached key payload1 signature = do
  let
    (nonceBytes, ciphertext) =
      ByteString.splitAt 12 payload1

  nonce :: Nonce <-
    bytesToNonce nonceBytes

  decryptDetached_ key nonce ciphertext signature

decryptDetached_ ::
     SecretKey
  -> Nonce
  -> ByteString
  -> Signature
  -> Maybe ByteString
decryptDetached_ key nonce ciphertext (Signature signatureBytes) = do
  expectedAuth :: Poly1305.Auth <-
    bytesToAuth signatureBytes

  let
    (plaintext, actualAuth) =
      aeadDecrypt key nonce ciphertext

  guard (actualAuth == expectedAuth)

  pure plaintext

-- | A variant of 'decrypt' suitable for decrypting a sequence of messages.
decryptSequence ::
     forall m.
     Monad m
  => SecretKey -- ^ Secret key
  -> ListT m ByteString -- ^ Ciphertext sequence
  -> ListT (MaybeT m) ByteString -- ^ Plaintext sequence
decryptSequence key payload0 =
  lift (lift (ListT.next payload0)) >>= \case
    ListT.Nil ->
      lift empty

    ListT.Cons nonceBytes ciphertext ->
      case bytesToNonce nonceBytes of
        Nothing ->
          lift empty

        Just nonce ->
          ListT.unfold step (nonce, ciphertext)

  where
    step ::
         (Nonce, ListT m ByteString)
      -> MaybeT m (Maybe (ByteString, (Nonce, ListT m ByteString)))
    step (nonce, payload) =
      lift (ListT.next payload) >>= \case
        ListT.Nil ->
          pure Nothing

        ListT.Cons x xs ->
          let
            (signature, ciphertext) =
              ByteString.splitAt 16 x
          in
            case decryptDetached_ key nonce ciphertext (Signature signature) of
              Nothing ->
                empty

              Just plaintext ->
                pure (Just (plaintext, (succ nonce, xs)))


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
sign_ key =
  ByteArray.convert . HMAC.hmac @_ @_ @Hash.Blake2b_256 (deriveKey key)

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
sipkey key =
  unsafeDupablePerformIO
    (ByteArray.withByteArray (deriveKey key) $ \ptr -> do
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
