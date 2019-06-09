-- | Helper functions for common encodings.

module H2NA.Encoding
  ( -- * Hexadecimal
    encodeHex
  , decodeHex
    -- * Base64
  , encodeBase64
  , decodeBase64
    -- ** URL-safe variant
  , encodeUrlSafeBase64
  , decodeUrlSafeBase64
  ) where

import Data.ByteString
import Data.ByteArray.Encoding


encodeHex :: ByteString -> ByteString
encodeHex =
  convertToBase Base16

decodeHex :: ByteString -> Maybe ByteString
decodeHex =
  either (const Nothing) Just . convertFromBase Base16

encodeBase64 :: ByteString -> ByteString
encodeBase64 =
  convertToBase Base64

decodeBase64 :: ByteString -> Maybe ByteString
decodeBase64 =
  either (const Nothing) Just . convertFromBase Base64

encodeUrlSafeBase64 :: ByteString -> ByteString
encodeUrlSafeBase64 =
  convertToBase Base64URLUnpadded

decodeUrlSafeBase64 :: ByteString -> Maybe ByteString
decodeUrlSafeBase64 =
  either (const Nothing) Just . convertFromBase Base64URLUnpadded
