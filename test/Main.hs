module Main where

import H2NA

import Control.Monad.Trans.Maybe
import Data.ByteString           (ByteString)
import Data.Function
import Data.Functor.Identity
import Data.Text                 (Text)
import Hedgehog
import Test.Tasty
import Test.Tasty.Hedgehog

import qualified Control.Foldl    as Foldl
import qualified List.Transformer as ListT
import qualified Hedgehog.Gen     as Gen
import qualified Hedgehog.Range   as Range


main :: IO ()
main =
  defaultMain tests

tests :: TestTree
tests =
  testGroup "tests"
    [ testProperty "hash/verify" $ withTests 1 $ property do
        password <- forAll genPassword
        digest <- hashPassword password
        assert (verifyPassword password digest)

    , testProperty "encrypt/decrypt" $ property do
        plaintext <- forAll genPlaintext
        key <- generateSecretKey
        nonce <- generateNonce
        decrypt key (encrypt key nonce plaintext) === Just plaintext

    , testProperty "encrypt/decrypt detached" $ property do
        plaintext <- forAll genPlaintext
        key <- generateSecretKey
        nonce <- generateNonce
        let (ciphertext, signature) = encryptDetached key nonce plaintext
        decryptDetached key ciphertext signature === Just plaintext

    , testProperty "encrypt/decrypt sequence" $ property do
        plaintexts <- forAll (Gen.list (Range.linear 0 10) genPlaintext)
        key <- generateSecretKey
        nonce <- generateNonce

        (plaintexts
          & ListT.select
          & encryptSequence key nonce
          & decryptSequence key
          & Foldl.purely ListT.fold Foldl.list
          & runMaybeT
          & runIdentity)
          === Just plaintexts

    , testProperty "encryptFor/decryptFrom" $ property do
        plaintext <- forAll genPlaintext
        sk1 <- generateSecretKey
        let pk1 = derivePublicKey sk1
        sk2 <- generateSecretKey
        let pk2 = derivePublicKey sk2
        nonce <- generateNonce
        decryptFrom pk1 sk2 (encryptFor sk1 pk2 nonce plaintext) === Just plaintext

    , testProperty "encrypt/decrypt detached" $ property do
        plaintext <- forAll genPlaintext
        nonce <- generateNonce
        sk1 <- generateSecretKey
        let pk1 = derivePublicKey sk1
        sk2 <- generateSecretKey
        let pk2 = derivePublicKey sk2
        let (ciphertext, signature) = encryptDetachedFor sk1 pk2 nonce plaintext
        decryptDetachedFrom pk1 sk2 ciphertext signature === Just plaintext

    , testProperty "encrypt/decrypt sequence" $ property do
        plaintexts <- forAll (Gen.list (Range.linear 0 10) genPlaintext)
        sk1 <- generateSecretKey
        let pk1 = derivePublicKey sk1
        sk2 <- generateSecretKey
        let pk2 = derivePublicKey sk2
        nonce <- generateNonce

        (plaintexts
          & ListT.select
          & encryptSequenceFor sk1 pk2 nonce
          & decryptSequenceFrom pk1 sk2
          & Foldl.purely ListT.fold Foldl.list
          & runMaybeT
          & runIdentity)
          === Just plaintexts
    ]

genPassword :: Gen Text
genPassword =
  Gen.text (Range.linear 1 10) Gen.unicode

genPlaintext :: Gen ByteString
genPlaintext =
  Gen.bytes (Range.linear 0 4096)
