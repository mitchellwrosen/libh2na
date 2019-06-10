module H2NA.Internal.Sign
  ( sign
  , shortsign
  ) where

import H2NA.Internal.KDF       (deriveKey)
import H2NA.Internal.SecretKey
import H2NA.Internal.Signature

import Data.Bits                 (unsafeShiftL, (.|.))
import Data.ByteString           (ByteString)
import Data.Coerce               (coerce)
import Data.Word                 (Word64, Word8)
import Foreign.Ptr               (plusPtr)
import Foreign.Storable          (peek)
import System.IO.Unsafe          (unsafeDupablePerformIO)

import qualified Crypto.Hash.Algorithms as Hash
import qualified Crypto.MAC.HMAC        as HMAC
import qualified Data.ByteArray         as ByteArray
import qualified Data.ByteArray.Hash    as ByteArray.Hash


-- | Sign a message with a secret key, producing a 32-byte signature.
--
-- To verify the authenticity of a message was signed by a particular secret
-- key, simply re-sign the message and compare the signatures for equality.
--
-- /Implementation/: @HKDF@, @HMAC-BLAKE2b-256@
sign ::
     SecretKey -- ^ Secret key
  -> ByteString -- ^ Message
  -> Signature -- ^ Signature
sign =
  coerce sign_

sign_ :: SecretKey -> ByteString -> ByteString
sign_ key message =
  ByteArray.convert digest
  where
    digest :: HMAC.HMAC Hash.Blake2b_256
    digest =
      HMAC.hmac
        (deriveKey (secretKeyToPseudoRandomMaterial key))
        message

-- | Sign a message with a secret key.
--
-- To verify the authenticity of a message was signed by a particular secret
-- key, simply re-sign the message and compare the signatures for equality.
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
    (ByteArray.withByteArray (deriveKey (secretKeyToPseudoRandomMaterial key)) $ \ptr -> do
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
