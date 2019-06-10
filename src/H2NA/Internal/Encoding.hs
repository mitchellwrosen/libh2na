-- | Helper functions for common encodings.

module H2NA.Internal.Encoding
  ( encodeHex
  , decodeHex
  , encodeBase64
  , decodeBase64
  , encodeUrlSafeBase64
  , decodeUrlSafeBase64
  ) where

import Data.ByteString
import Data.ByteArray.Encoding


-- | Hexadecimal encoding.
encodeHex :: ByteString -> ByteString
encodeHex =
  convertToBase Base16

-- | Hexadecimal decoding.
decodeHex :: ByteString -> Maybe ByteString
decodeHex =
  either (const Nothing) Just . convertFromBase Base16

-- | Base64 encoding.
encodeBase64 :: ByteString -> ByteString
encodeBase64 =
  convertToBase Base64

-- | Base64 decoding.
decodeBase64 :: ByteString -> Maybe ByteString
decodeBase64 =
  either (const Nothing) Just . convertFromBase Base64

-- | URL-safe base64 encoding.
encodeUrlSafeBase64 :: ByteString -> ByteString
encodeUrlSafeBase64 =
  convertToBase Base64URLUnpadded

-- | URL-safe base64 decoding.
decodeUrlSafeBase64 :: ByteString -> Maybe ByteString
decodeUrlSafeBase64 =
  either (const Nothing) Just . convertFromBase Base64URLUnpadded
