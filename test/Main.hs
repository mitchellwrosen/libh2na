module Main where

import H2NA

import Control.Monad.Trans.Maybe
import Data.ByteString           (ByteString)
import Data.Function
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
        ciphertext <- encrypt key plaintext
        decrypt key ciphertext === Just plaintext

    , testProperty "encrypt/decrypt detached" $ property do
        plaintext <- forAll genPlaintext
        key <- generateSecretKey
        (ciphertext, signature) <- encryptDetached key plaintext
        decryptDetached key ciphertext signature === Just plaintext

    , testProperty "encrypt/decrypt sequence" $ property do
        plaintexts <- forAll (Gen.list (Range.linear 0 10) genPlaintext)
        key <- generateSecretKey

        plaintexts' <-
          plaintexts
            & ListT.select
            & encryptSequence key
            & decryptSequence key
            & Foldl.purely ListT.fold Foldl.list
            & runMaybeT
        plaintexts' === Just plaintexts

    , testProperty "encryptFor/decryptFrom" $ property do
        plaintext <- forAll genPlaintext
        sk1 <- generateSecretKey
        let pk1 = derivePublicKey sk1
        sk2 <- generateSecretKey
        let pk2 = derivePublicKey sk2
        ciphertext <- encryptFor sk1 pk2 plaintext
        decryptFrom pk1 sk2 ciphertext === Just plaintext

    , testProperty "encrypt/decrypt detached" $ property do
        plaintext <- forAll genPlaintext
        sk1 <- generateSecretKey
        let pk1 = derivePublicKey sk1
        sk2 <- generateSecretKey
        let pk2 = derivePublicKey sk2
        (ciphertext, signature) <- encryptDetachedFor sk1 pk2 plaintext
        decryptDetachedFrom pk1 sk2 ciphertext signature === Just plaintext

    , testProperty "encrypt/decrypt sequence" $ property do
        plaintexts <- forAll (Gen.list (Range.linear 0 10) genPlaintext)
        sk1 <- generateSecretKey
        let pk1 = derivePublicKey sk1
        sk2 <- generateSecretKey
        let pk2 = derivePublicKey sk2

        plaintexts' <-
          plaintexts
            & ListT.select
            & encryptSequenceFor sk1 pk2
            & decryptSequenceFrom pk1 sk2
            & Foldl.purely ListT.fold Foldl.list
            & runMaybeT
        plaintexts' === Just plaintexts
    ]

genPassword :: Gen Text
genPassword =
  Gen.text (Range.linear 1 10) Gen.unicode

genPlaintext :: Gen ByteString
genPlaintext =
  Gen.bytes (Range.linear 0 4096)
