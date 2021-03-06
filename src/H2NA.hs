module H2NA
  ( -- * Secret key cryptography
    -- ** Encryption
    encrypt
  , encryptDetached
  , encryptSequence
    -- ** Decryption
  , decrypt
  , decryptDetached
  , decryptSequence
    -- ** Signing
  , sign
  , shortsign
    -- * Public key cryptography
    -- ** Encryption
  , encryptFor
  , encryptDetachedFor
  , encryptSequenceFor
    -- *** Anonymous encryption
  , encryptAnonymouslyFor
    -- ** Decryption
  , decryptFrom
  , decryptDetachedFrom
  , decryptSequenceFrom
    -- * Passwords
  , hashPassword
  , verifyPassword
    -- * Hashing
  , hash
  , hashFold
    -- * Encoding
    -- ** Hexadecimal
  , encodeHex
  , decodeHex
    -- ** Base64
  , encodeBase64
  , decodeBase64
    -- *** URL-safe variant
  , encodeUrlSafeBase64
  , decodeUrlSafeBase64
    -- * Types
    -- ** Secret key
  , SecretKey
  , generateSecretKey
  , derivePublicKey
    -- *** Conversion
  , secretKeyToBytes
  , bytesToSecretKey
    -- ** Public key
  , PublicKey
    -- *** Conversion
  , publicKeyToBytes
  , bytesToPublicKey
    -- ** Signature
  , Signature(..)
  ) where

import H2NA.Internal.Decrypt
import H2NA.Internal.Encoding
import H2NA.Internal.Encrypt
import H2NA.Internal.Hash
import H2NA.Internal.Password
import H2NA.Internal.PublicKey
import H2NA.Internal.SecretKey
import H2NA.Internal.Sign
import H2NA.Internal.Signature
