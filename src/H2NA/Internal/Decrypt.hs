module H2NA.Internal.Decrypt
  ( decrypt
  , decryptDetached
  , decryptSequence

  , decryptFrom
  , decryptDetachedFrom
  , decryptSequenceFrom
  ) where

import H2NA.Internal.AEAD
import H2NA.Internal.DiffieHellmanSecret
import H2NA.Internal.PseudoRandomMaterial (PseudoRandomMaterial)
import H2NA.Internal.PublicKey
import H2NA.Internal.SecretKey
import H2NA.Internal.Signature

import Control.Applicative       (empty)
import Control.Monad             (guard)
import Control.Monad.Trans.Class
import Control.Monad.Trans.Maybe
import Data.ByteArray            (ByteArrayAccess)
import Data.ByteString           (ByteString)
import List.Transformer          (ListT)

import qualified Crypto.MAC.Poly1305    as Poly1305
import qualified Data.ByteString        as ByteString
import qualified List.Transformer       as ListT


-- | Decrypt and verify a message.
--
-- /Implementation/: @ChaCha20@, @HKDF@, @Poly1305@
decrypt ::
     SecretKey -- ^ Secret key
  -> ByteString -- ^ Ciphertext
  -> Maybe ByteString -- ^ Plaintext
decrypt key =
  decryptWith (secretKeyToPseudoRandomMaterial key)

-- | Decrypt and verify a message intended for a single recipient.
--
-- /Implementation/: @ChaCha20@, @HKDF@, @Poly1305@
decryptFrom ::
     PublicKey -- ^ Sender public key
  -> SecretKey -- ^ Receiver secret key
  -> ByteString -- ^ Ciphertext
  -> Maybe ByteString -- ^ Plaintext
decryptFrom pk sk =
  decryptWith (diffieHellmanSecretToPseudoRandomMaterial sk pk)

decryptWith ::
     ByteArrayAccess a
  => PseudoRandomMaterial a
  -> ByteString
  -> Maybe ByteString
decryptWith key payload0 =
  decrypt_
    key
    nonce
    ciphertext
    signature

  where
    (signature, payload1) =
      ByteString.splitAt 16 payload0

    (nonce, ciphertext) =
      ByteString.splitAt 12 payload1

-- | A variant of 'decrypt' that is used to decrypt messages encrypted with
-- 'encryptDetached'.
decryptDetached ::
     SecretKey -- ^ Secret key
  -> ByteString -- ^ Ciphertext
  -> Signature -- ^ Signature
  -> Maybe ByteString -- ^ Plaintext
decryptDetached key =
  decryptDetachedWith (secretKeyToPseudoRandomMaterial key)

-- | A variant of 'decryptFrom' that is used to decrypt messages encrypted with
-- 'encryptDetachedFor'.
decryptDetachedFrom ::
     PublicKey -- ^ Sender public key
  -> SecretKey -- ^ Receiver secret key
  -> ByteString -- ^ Ciphertext
  -> Signature -- ^ Signature
  -> Maybe ByteString -- ^ Plaintext
decryptDetachedFrom pk sk =
  decryptDetachedWith (diffieHellmanSecretToPseudoRandomMaterial sk pk)

decryptDetachedWith ::
     ByteArrayAccess a
  => PseudoRandomMaterial a
  -> ByteString
  -> Signature
  -> Maybe ByteString
decryptDetachedWith key payload (Signature signature) =
  decrypt_
    key
    nonce
    ciphertext
    signature

  where
    (nonce, ciphertext) =
      ByteString.splitAt 12 payload

-- | A variant of 'decrypt' suitable for decrypting a sequence of messages.
decryptSequence ::
     Monad m
  => SecretKey -- ^ Secret key
  -> ListT m ByteString -- ^ Ciphertext sequence
  -> ListT (MaybeT m) ByteString -- ^ Plaintext sequence
decryptSequence key =
  decryptSequenceWith (secretKeyToPseudoRandomMaterial key)

-- | A variant of 'decryptFrom' suitable for decrypting a sequence of messages.
decryptSequenceFrom ::
     Monad m
  => PublicKey -- ^ Sender public key
  -> SecretKey -- ^ Receiver secret key
  -> ListT m ByteString -- ^ Ciphertext sequence
  -> ListT (MaybeT m) ByteString -- ^ Plaintext sequence
decryptSequenceFrom pk sk =
  decryptSequenceWith (diffieHellmanSecretToPseudoRandomMaterial sk pk)

decryptSequenceWith ::
     forall a m.
     (ByteArrayAccess a, Monad m)
  => PseudoRandomMaterial a
  -> ListT m ByteString
  -> ListT (MaybeT m) ByteString
decryptSequenceWith key payload0 =
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
            case decrypt__ key nonce ciphertext signature of
              Nothing ->
                empty

              Just plaintext ->
                pure (Just (plaintext, (succ nonce, xs)))

decrypt_ ::
     ByteArrayAccess a
  => PseudoRandomMaterial a -- Key
  -> ByteString -- Nonce
  -> ByteString -- Ciphertext
  -> ByteString -- Signature
  -> Maybe ByteString -- Plaintext
decrypt_ key nonceBytes ciphertext signature = do
  nonce :: Nonce <-
    bytesToNonce nonceBytes
  decrypt__ key nonce ciphertext signature

decrypt__ ::
     ByteArrayAccess a
  => PseudoRandomMaterial a -- Key
  -> Nonce -- Nonce
  -> ByteString -- Ciphertext
  -> ByteString -- Signature
  -> Maybe ByteString -- Plaintext
decrypt__ key nonce ciphertext signature = do
  expectedAuth :: Poly1305.Auth <-
    bytesToAuth signature

  let
    (plaintext, actualAuth) =
      aeadDecrypt key nonce ciphertext

  guard (actualAuth == expectedAuth)

  pure plaintext
