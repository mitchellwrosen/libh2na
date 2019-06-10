module H2NA.Internal.Encrypt
  ( encrypt
  , encryptDetached
  , encryptSequence

  , encryptFor
  , encryptDetachedFor
  , encryptSequenceFor

  , encryptAnonymouslyFor
  ) where

import H2NA.Internal.AEAD                 (Nonce, aeadEncrypt, generateNonce,
                                           nonceToBytes)
import H2NA.Internal.DiffieHellmanSecret
import H2NA.Internal.PseudoRandomMaterial (PseudoRandomMaterial)
import H2NA.Internal.PublicKey            (PublicKey, publicKeyToBytes)
import H2NA.Internal.SecretKey            (SecretKey, derivePublicKey,
                                           generateSecretKey,
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
-- The wire format of the ciphertext is as follows:
--
-- @
-- +------------------+----------------------+------------+
-- | Nonce (12 bytes) | Signature (16 bytes) | Ciphertext |
-- +------------------+----------------------+------------+
-- @
--
-- /Implementation/: @ChaCha20@, @HKDF@, @Poly1305@
encrypt ::
     MonadIO m
  => SecretKey -- ^ Secret key
  -> ByteString -- ^ Plaintext
  -> m ByteString -- ^ Ciphertext
encrypt key plaintext = do
  nonce <- generateNonce
  pure (encryptPure key nonce plaintext)

encryptPure ::
     SecretKey -- ^ Secret key
  -> Nonce -- ^ Nonce
  -> ByteString -- ^ Plaintext
  -> ByteString -- ^ Ciphertext
encryptPure key =
  encryptWithPure (secretKeyToPseudoRandomMaterial key)

-- | Encrypt and sign a message intended for a single recipient, which can
-- be decrypted using her secret key and the sender's public key.
--
-- The wire format of the ciphertext is as follows:
--
-- @
-- +------------------+----------------------+------------+
-- | Nonce (12 bytes) | Signature (16 bytes) | Ciphertext |
-- +------------------+----------------------+------------+
-- @
--
-- /Implementation/: @ChaCha20@, @HKDF@, @Poly1305@
encryptFor ::
     MonadIO m
  => SecretKey -- ^ Sender secret key
  -> PublicKey -- ^ Receiver public key
  -> ByteString -- ^ Plaintext
  -> m ByteString -- ^ Ciphertext
encryptFor secretKey publicKey plaintext = do
  nonce <- generateNonce
  pure (encryptForPure secretKey publicKey nonce plaintext)

encryptForPure ::
     SecretKey
  -> PublicKey
  -> Nonce
  -> ByteString
  -> ByteString
encryptForPure sk pk =
  encryptWithPure (diffieHellmanSecretToPseudoRandomMaterial sk pk)

encryptWithPure ::
     ByteArrayAccess a
  => PseudoRandomMaterial a
  -> Nonce
  -> ByteString
  -> ByteString
encryptWithPure key nonce plaintext =
  let
    (ciphertext, auth) =
      aeadEncrypt key nonce plaintext
  in
    ByteString.concat
      [ nonceToBytes nonce
      , coerce (authToSignature auth)
      , ciphertext
      ]

-- | A variant of 'encrypt' that does not combine the ciphertext with the
-- message signature.
--
-- This is useful if you want to store the signature separately.
--
-- The wire format of the ciphertext is as follows:
--
-- @
-- +------------------+------------+
-- | Nonce (12 bytes) | Ciphertext |
-- +------------------+------------+
-- @
encryptDetached ::
     MonadIO m
  => SecretKey -- ^ Secret key
  -> ByteString -- ^ Plaintext
  -> m (ByteString, Signature) -- ^ Ciphertext and signature
encryptDetached key plaintext = do
  nonce <- generateNonce
  pure (encryptDetachedPure key nonce plaintext)

encryptDetachedPure ::
     SecretKey
  -> Nonce
  -> ByteString
  -> (ByteString, Signature)
encryptDetachedPure key =
  encryptDetachedWithPure (secretKeyToPseudoRandomMaterial key)

-- | A variant of 'encryptFor' that does not combine the ciphertext with the
-- message signature.
--
-- This is useful if you want to store the signature separately.
--
-- The wire format of the ciphertext is as follows:
--
-- @
-- +------------------+------------+
-- | Nonce (12 bytes) | Ciphertext |
-- +------------------+------------+
-- @
encryptDetachedFor ::
     MonadIO m
  => SecretKey -- ^ Sender secret key
  -> PublicKey -- ^ Receiver public key
  -> ByteString -- ^ Plaintext
  -> m (ByteString, Signature) -- ^ Ciphertext and signature
encryptDetachedFor sk pk plaintext = do
  nonce <- generateNonce
  pure (encryptDetachedForPure sk pk nonce plaintext)

encryptDetachedForPure ::
     SecretKey
  -> PublicKey
  -> Nonce
  -> ByteString
  -> (ByteString, Signature)
encryptDetachedForPure sk pk =
  encryptDetachedWithPure (diffieHellmanSecretToPseudoRandomMaterial sk pk)

encryptDetachedWithPure ::
     ByteArrayAccess a
  => PseudoRandomMaterial a
  -> Nonce
  -> ByteString
  -> (ByteString, Signature)
encryptDetachedWithPure key nonce plaintext =
  let
    (ciphertext, auth) =
      aeadEncrypt key nonce plaintext
  in
    (nonceToBytes nonce <> ciphertext, authToSignature auth)

-- | A variant of 'encrypt' suitable for encrypting a sequence of messages.
--
-- The wire format of the ciphertext sequence is as follows:
--
-- @
-- +--------------------------+
-- | Initial nonce (12 bytes) |
-- +------------------------+--------------+
-- | Signature 1 (16 bytes) | Ciphertext 1 |
-- +------------------------+--------------+
-- | Signature 2 (16 bytes) | Ciphertext 2 |
-- +------------------------+--------------+
--   ⋮    ⋮    ⋮    ⋮    ⋮    ⋮    ⋮
-- @
encryptSequence ::
     MonadIO m
  => SecretKey -- ^ Secret key
  -> ListT m ByteString -- ^ Plaintext sequence
  -> ListT m ByteString -- ^ Ciphertext sequence
encryptSequence key plaintext = do
  nonce <- liftIO generateNonce
  encryptSequencePure key nonce plaintext

encryptSequencePure ::
     Monad m
  => SecretKey -- ^ Secret key
  -> Nonce -- ^ Initial nonce
  -> ListT m ByteString -- ^ Plaintext sequence
  -> ListT m ByteString -- ^ Ciphertext sequence
encryptSequencePure key =
  encryptSequenceWithPure (secretKeyToPseudoRandomMaterial key)

-- | A variant of 'encryptFor' suitable for encrypting a sequence of messages.
--
-- The wire format of the ciphertext sequence is as follows:
--
-- @
-- +--------------------------+
-- | Initial nonce (12 bytes) |
-- +------------------------+--------------+
-- | Signature 1 (16 bytes) | Ciphertext 1 |
-- +------------------------+--------------+
-- | Signature 2 (16 bytes) | Ciphertext 2 |
-- +------------------------+--------------+
--   ⋮    ⋮    ⋮    ⋮    ⋮    ⋮    ⋮
-- @
encryptSequenceFor ::
     MonadIO m
  => SecretKey -- ^ Sender secret key
  -> PublicKey -- ^ Receiver secret key
  -> ListT m ByteString -- ^ Plaintext sequence
  -> ListT m ByteString -- ^ Ciphertext sequence
encryptSequenceFor secretKey publicKey plaintext = do
  nonce <- liftIO generateNonce
  encryptSequenceForPure secretKey publicKey nonce plaintext

encryptSequenceForPure ::
     Monad m
  => SecretKey -- ^ Sender secret key
  -> PublicKey -- ^ Receiver public key
  -> Nonce -- ^ Initial nonce
  -> ListT m ByteString -- ^ Plaintext sequence
  -> ListT m ByteString -- ^ Ciphertext sequence
encryptSequenceForPure sk pk =
  encryptSequenceWithPure (diffieHellmanSecretToPseudoRandomMaterial sk pk)

encryptSequenceWithPure ::
     forall a m.
     (ByteArrayAccess a, Monad m)
  => PseudoRandomMaterial a
  -> Nonce
  -> ListT m ByteString
  -> ListT m ByteString
encryptSequenceWithPure key nonce0 plaintext0 =
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


-- | A variant of 'encryptFor' that uses an ephemeral secret key, so the
-- recipient cannot verify the identity of the sender.
--
-- The wire format of the ciphertext is as follows:
--
-- @
-- +------------------+---------------------------------+------------+
-- | Nonce (12 bytes) | Ephemeral public key (32 bytes) | Ciphertext |
-- +------------------+---------------------------------+------------+
-- @
--
-- /Implementation/: @ChaCha20@, @HKDF@, @Poly1305@
encryptAnonymouslyFor ::
     MonadIO m
  => PublicKey -- ^ Receiver public key
  -> ByteString -- ^ Plaintext
  -> m ByteString -- ^ Ciphertext
encryptAnonymouslyFor publicKey plaintext = do
  nonce <- generateNonce
  secretKey <- generateSecretKey

  let
    (ciphertext, auth) =
      aeadEncrypt
        (diffieHellmanSecretToPseudoRandomMaterial secretKey publicKey)
        nonce
        plaintext

  pure
    (ByteString.concat
      [ nonceToBytes nonce
      , publicKeyToBytes (derivePublicKey secretKey)
      , coerce (authToSignature auth)
      , ciphertext
      ])
