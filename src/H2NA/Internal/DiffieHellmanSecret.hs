module H2NA.Internal.DiffieHellmanSecret
  ( diffieHellmanSecretToPseudoRandomMaterial
  ) where

import H2NA.Internal.PseudoRandomMaterial (PseudoRandomMaterial(..))
import H2NA.Internal.PublicKey            (PublicKey(..))
import H2NA.Internal.SecretKey            (SecretKey(..))

import qualified Crypto.PubKey.Curve25519 as Curve25519


diffieHellmanSecretToPseudoRandomMaterial ::
     SecretKey
  -> PublicKey
  -> PseudoRandomMaterial Curve25519.DhSecret
diffieHellmanSecretToPseudoRandomMaterial (SecretKey sk) (PublicKey pk) =
  PseudoRandomMaterial (Curve25519.dh pk sk)
