{-# OPTIONS_GHC -fno-warn-incomplete-patterns #-}

module H2NA.Internal.Password
  ( hashPassword
  , verifyPassword
  ) where

import H2NA.Internal.Encoding (decodeBase64)

import Control.Monad          (guard, (>=>))
import Control.Monad.IO.Class
import Crypto.Error           (CryptoFailable(..))
import Data.ByteArray         (Bytes)
import Data.ByteString        (ByteString)
import Data.Foldable          (fold)
import Data.Text              (Text)
import Data.Word              (Word32)

import qualified Crypto.KDF.Argon2          as Argon2
import qualified Crypto.Random              as Random
import qualified Data.ByteArray.Encoding    as ByteArray.Encoding
import qualified Data.Text                  as Text
import qualified Data.Text.Encoding         as Text
import qualified Data.Text.Lazy             as Text.Lazy
import qualified Data.Text.Lazy.Builder     as Text.Builder
import qualified Data.Text.Lazy.Builder     as Text (Builder)
import qualified Data.Text.Lazy.Builder.Int as Text.Builder
import qualified Data.Text.Read             as Text (decimal)


-- | Hash a password.
--
-- @
-- > hashPassword "hunter2"
-- "$argon2id$v=13$m=131072,t=3,p=4$ZWmBnqJ99BzcUZe1j24Gjw==$rojyj6gweIkcd39QQR8S1oxFJclpciBgYSuxvcGxfRo="
-- @
--
-- /Implementation/: @Argon2id@
hashPassword ::
     MonadIO m
  => Text -- ^ Password
  -> m Text -- ^ Digest
hashPassword password = liftIO $ do
  salt :: Bytes <-
    Random.getRandomBytes 16

  case Argon2.hash options (Text.encodeUtf8 password) salt 32 of
    CryptoPassed digest ->
      pure (formatDigest options salt digest)

  where
    options :: Argon2.Options
    options =
      Argon2.Options
        { Argon2.iterations = 3
        , Argon2.memory = 2 ^ (17 :: Int)
        , Argon2.parallelism = 4
        , Argon2.variant = Argon2.Argon2id
        , Argon2.version = Argon2.Version13
        }

-- | Verify a password hashed with 'hashPassword'.
--
-- @
-- > verifyPassword "hunter2" "$argon2id$v=13$m=131072,t=3,p=4$ZWmBnqJ99BzcUZe1j24Gjw==$rojyj6gweIkcd39QQR8S1oxFJclpciBgYSuxvcGxfRo="
-- True
-- @
--
-- /Implementation/: @Argon2id@
verifyPassword ::
     Text -- ^ Password
  -> Text -- ^ Digest
  -> Bool
verifyPassword password digest =
  (== Just ()) $ do
    (options, salt, pass) <-
      parseDigest digest

    guard
      (Argon2.hash options (Text.encodeUtf8 password) salt 32 ==
        CryptoPassed pass)

formatDigest ::
     Argon2.Options
  -> Bytes
  -> Bytes
  -> Text
formatDigest options salt digest =
  Text.Lazy.toStrict
    (Text.Builder.toLazyText
      (fold
        [ variant
        , version
        , "$m=", memory
        , ",t=", iterations
        , ",p=", parallelism
        , "$", bytesToBuilder salt
        , "$", bytesToBuilder digest
        ]))

  where
    variant :: Text.Builder
    variant =
      case Argon2.variant options of
        Argon2.Argon2d -> "$argon2d"
        Argon2.Argon2i -> "$argon2i"
        Argon2.Argon2id -> "$argon2id"

    version :: Text.Builder
    version =
      case Argon2.version options of
        Argon2.Version10 -> "$v=10"
        Argon2.Version13 -> "$v=13"

    memory :: Text.Builder
    memory =
      Text.Builder.decimal (Argon2.memory options)

    iterations :: Text.Builder
    iterations =
      Text.Builder.decimal (Argon2.iterations options)

    parallelism :: Text.Builder
    parallelism =
      Text.Builder.decimal (Argon2.parallelism options)

    bytesToBuilder :: Bytes -> Text.Builder
    bytesToBuilder =
      Text.Builder.fromText .
      Text.decodeUtf8 .
      ByteArray.Encoding.convertToBase ByteArray.Encoding.Base64

parseDigest :: Text -> Maybe (Argon2.Options, ByteString, ByteString)
parseDigest digest = do
  [   ""
    , parseVariant -> Just variant
    , Text.stripPrefix "v=" -> Just (parseVersion -> Just version)
    , Text.split (== ',') ->
      [ Text.stripPrefix "m=" -> Just (readWord32 -> Just memory)
      , Text.stripPrefix "t=" -> Just (readWord32 -> Just iterations)
      , Text.stripPrefix "p=" -> Just (readWord32 -> Just parallelism)
      ]
    , unBase64 -> Just salt
    , unBase64 -> Just pass
    ] <- Just (Text.split (== '$') digest)

  let
    options :: Argon2.Options
    options =
      Argon2.Options
        { Argon2.iterations = iterations
        , Argon2.memory = memory
        , Argon2.parallelism = parallelism
        , Argon2.variant = variant
        , Argon2.version = version
        }

  pure (options, salt, pass)

  where
    parseVariant :: Text -> Maybe Argon2.Variant
    parseVariant = do
      Text.stripPrefix "argon2" >=> \case
        "d" -> Just Argon2.Argon2d
        "i" -> Just Argon2.Argon2i
        "id" -> Just Argon2.Argon2id
        _ -> Nothing

    parseVersion :: Text -> Maybe Argon2.Version
    parseVersion = \case
      "10" -> Just Argon2.Version10
      "13" -> Just Argon2.Version13
      _ -> Nothing

    unBase64 :: Text -> Maybe ByteString
    unBase64 =
      decodeBase64 . Text.encodeUtf8

    readWord32 :: Text -> Maybe Word32
    readWord32 =
      either (const Nothing) (Just . fst) . Text.decimal
