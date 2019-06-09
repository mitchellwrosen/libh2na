module H2NA.Internal.Encrypt
  ( encrypt
  , encryptIO
  , encryptDetached
  , encryptSequence
  , encryptSequenceIO

  , encryptFor
  , encryptForIO
  , encryptDetachedFor
  , encryptSequenceFor
  , encryptSequenceForIO
  ) where

import H2NA.Internal.AEAD                 (Nonce, aeadEncrypt, generateNonce,
                                           nonceToBytes)
import H2NA.Internal.DiffieHellmanSecret
import H2NA.Internal.PseudoRandomMaterial (PseudoRandomMaterial)
import H2NA.Internal.PublicKey            (PublicKey)
import H2NA.Internal.SecretKey            (SecretKey,
                                           secretKeyToPseudoRandomMaterial)
import H2NA.Internal.Signature            (Signature(..), authToSignature)

import Control.Applicative    ((<|>))
import Control.Monad.IO.Class
import Data.ByteArray         (ByteArrayAccess)
import Data.ByteString        (ByteString)
import Data.Coerce            (coerce)
import List.Transformer       (ListT)

import qualified Data.ByteString  as ByteString
import qualified List.Transformer as ListT


-- | Encrypt and sign a message, which can only be decrypted using the same
-- secret key.
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
encrypt key =
  encryptWith (secretKeyToPseudoRandomMaterial key)

-- | Encrypt and sign a message intended for a single recipient, which can
-- only be decrypted using his secret key and her public key, or his public key
-- and her secret key.
--
-- If the secret key is used more than once, then the nonce should be randomly
-- generated with 'generateNonce'. Otherwise, you may use 'zeroNonce'.
--
-- /Implementation/: @ChaCha20@, @HKDF@, @Poly1305@
encryptFor ::
     SecretKey -- ^ Sender secret key
  -> PublicKey -- ^ Receiver public key
  -> Nonce -- ^ Nonce
  -> ByteString -- ^ Plaintext
  -> ByteString -- ^ Ciphertext
encryptFor sk pk =
  encryptWith (diffieHellmanSecretToPseudoRandomMaterial sk pk)

encryptWith ::
     ByteArrayAccess a
  => PseudoRandomMaterial a
  -> Nonce
  -> ByteString
  -> ByteString
encryptWith key nonce plaintext =
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

-- | A variant of 'encryptFor' that generates a random nonce with
-- 'generateNonce'.
encryptForIO ::
     MonadIO m
  => SecretKey -- ^ Sender secret key
  -> PublicKey -- ^ Receiver public key
  -> ByteString -- ^ Plaintext
  -> m ByteString -- ^ Ciphertext
encryptForIO secretKey publicKey plaintext = do
  nonce <- generateNonce
  pure (encryptFor secretKey publicKey nonce plaintext)

-- | A variant of 'encrypt' that does not combine the ciphertext with the
-- message signature.
--
-- This is useful if you want to store the signature separately.
encryptDetached ::
     SecretKey -- ^ Secret key
  -> Nonce -- ^ Nonce
  -> ByteString -- ^ Plaintext
  -> (ByteString, Signature) -- ^ Ciphertext and signature
encryptDetached key =
  encryptDetachedWith (secretKeyToPseudoRandomMaterial key)

-- | A variant of 'encryptFor' that does not combine the ciphertext with the
-- message signature.
--
-- This is useful if you want to store the signature separately.
encryptDetachedFor ::
     SecretKey -- ^ Sender secret key
  -> PublicKey -- ^ Receiver public key
  -> Nonce -- ^ Nonce
  -> ByteString -- ^ Plaintext
  -> (ByteString, Signature) -- ^ Ciphertext and signature
encryptDetachedFor sk pk =
  encryptDetachedWith (diffieHellmanSecretToPseudoRandomMaterial sk pk)

encryptDetachedWith ::
     ByteArrayAccess a
  => PseudoRandomMaterial a
  -> Nonce
  -> ByteString
  -> (ByteString, Signature)
encryptDetachedWith key nonce plaintext =
  let
    (ciphertext, auth) =
      aeadEncrypt key nonce plaintext
  in
    (nonceToBytes nonce <> ciphertext, authToSignature auth)

-- | A variant of 'encrypt' suitable for encrypting a sequence of messages.
encryptSequence ::
     Monad m
  => SecretKey -- ^ Secret key
  -> Nonce -- ^ Nonce
  -> ListT m ByteString -- ^ Plaintext sequence
  -> ListT m ByteString -- ^ Ciphertext sequence
encryptSequence key =
  encryptSequenceWith (secretKeyToPseudoRandomMaterial key)

-- | A variant of 'encryptFor' suitable for encrypting a sequence of messages.
encryptSequenceFor ::
     Monad m
  => SecretKey -- ^ Sender secret key
  -> PublicKey -- ^ Receiver public key
  -> Nonce -- ^ Nonce
  -> ListT m ByteString -- ^ Plaintext sequence
  -> ListT m ByteString -- ^ Ciphertext sequence
encryptSequenceFor sk pk =
  encryptSequenceWith (diffieHellmanSecretToPseudoRandomMaterial sk pk)

-- | A variant of 'encrypt' suitable for encrypting a sequence of messages.
encryptSequenceWith ::
     forall a m.
     (ByteArrayAccess a, Monad m)
  => PseudoRandomMaterial a
  -> Nonce
  -> ListT m ByteString
  -> ListT m ByteString
encryptSequenceWith key nonce0 plaintext0 =
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
  => SecretKey -- ^ Secret key
  -> ListT m ByteString -- ^ Plaintext sequence
  -> ListT m ByteString -- ^ Ciphertext sequence
encryptSequenceIO key plaintext = do
  nonce <- liftIO generateNonce
  encryptSequence key nonce plaintext

-- | A variant of 'encryptSequenceFor' that generates a random nonce with
-- 'generateNonce'.
encryptSequenceForIO ::
     MonadIO m
  => SecretKey -- ^ Sender secret key
  -> PublicKey -- ^ Receiver secret key
  -> ListT m ByteString -- ^ Plaintext sequence
  -> ListT m ByteString -- ^ Ciphertext sequence
encryptSequenceForIO secretKey publicKey plaintext = do
  nonce <- liftIO generateNonce
  encryptSequenceFor secretKey publicKey nonce plaintext
