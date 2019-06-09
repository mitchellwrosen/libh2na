module Main where

import H2NA.Password
import H2NA.SecretBox
import H2NA.SecretKey

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
    [ testGroup "Password" passwordTests
    , testGroup "SecretBox" secretBoxTests
    ]

passwordTests :: [TestTree]
passwordTests =
  [ testProperty "hash/verify" $ withTests 1 $ property do
      password <- forAll genPassword
      digest <- hashPassword password
      assert (verifyPassword password digest)
  ]

secretBoxTests :: [TestTree]
secretBoxTests =
  [ testProperty "encrypt/decrypt" $ property do
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
  ]

genPassword :: Gen Text
genPassword =
  Gen.text (Range.linear 1 10) Gen.unicode

genPlaintext :: Gen ByteString
genPlaintext =
  Gen.bytes (Range.linear 0 4096)
