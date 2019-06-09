module Main where

import H2NA.SecretBox
import H2NA.SecretKey

import Control.Monad.IO.Class
import Data.ByteString (ByteString)
import Hedgehog
import Test.Tasty
import Test.Tasty.Hedgehog

import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range

main :: IO ()
main =
  defaultMain tests

tests :: TestTree
tests =
  testGroup "tests"
    [ testGroup "SecretBox" secretBoxTests
    ]

secretBoxTests :: [TestTree]
secretBoxTests =
  [ prop "encrypt/decrypt" do
      plaintext <- forAll genPlaintext
      key <- generateSecretKey
      nonce <- generateNonce
      decrypt key (encrypt key nonce plaintext) === Just plaintext
  ]

genPlaintext :: Gen ByteString
genPlaintext =
  Gen.bytes (Range.linear 0 4096)

prop :: TestName -> PropertyT IO () -> TestTree
prop name p =
  testProperty name (property p)
