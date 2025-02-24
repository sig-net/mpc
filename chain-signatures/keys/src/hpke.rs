use std::{fmt, io};

use borsh::{self, BorshDeserialize, BorshSerialize};
use hpke::{
    OpModeR,
    aead::{AeadTag, ChaCha20Poly1305},
    kdf::HkdfSha384,
    kem::X25519HkdfSha256,
};
use serde::{Deserialize, Serialize};

/// This can be used to customize the generated key. This will be used as a sort of
/// versioning mechanism for the key. It's additional context about who is encrypting
/// the key. This is used to prevent a key from being used in a context it was not
/// supposed to be used for.
const INFO_ENTROPY: &[u8] = b"mpc-key-v1";

// Interchangeable type parameters for the HPKE context.
pub type Kem = X25519HkdfSha256;
pub type Aead = ChaCha20Poly1305;
pub type Kdf = HkdfSha384;
pub type Error = hpke::HpkeError;

#[derive(Serialize, Deserialize)]
pub struct Ciphered {
    pub encapped_key: EncappedKey,
    pub text: CipherText,
    pub tag: Tag,
}

#[derive(Serialize, Deserialize)]
pub struct Tag(AeadTag<Aead>);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey(<Kem as hpke::Kem>::PublicKey);

// NOTE: Arc is used to hack up the fact that the internal private key does not have Send constraint.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretKey(<Kem as hpke::Kem>::PrivateKey);

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let key = hex::encode(self.to_bytes());
        let debug_key = format!("{}[..]", &key[..key.len() - 4]);
        f.debug_struct("SecretKey")
            .field("key", &debug_key)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EncappedKey(<Kem as hpke::Kem>::EncappedKey);

// Series of bytes that have been previously encoded/encrypted.
pub type CipherText = Vec<u8>;

impl PublicKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        hpke::Serializable::to_bytes(&self.0).into()
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, hpke::HpkeError> {
        Ok(Self(hpke::Deserializable::from_bytes(bytes)?))
    }

    /// Assumes the bytes are correctly formatted.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::try_from_bytes(bytes).expect("invalid bytes")
    }

    pub fn encrypt(&self, msg: &[u8], associated_data: &[u8]) -> Result<Ciphered, hpke::HpkeError> {
        let mut csprng = <rand::rngs::StdRng as rand::SeedableRng>::from_entropy();

        // Encapsulate a key and use the resulting shared secret to encrypt a message. The AEAD context
        // is what you use to encrypt.
        let (encapped_key, mut sender_ctx) = hpke::setup_sender::<Aead, Kdf, Kem, _>(
            &hpke::OpModeS::Base,
            &self.0,
            INFO_ENTROPY,
            &mut csprng,
        )?;

        // On success, seal_in_place_detached() will encrypt the plaintext in place
        let mut ciphertext = msg.to_vec();
        let tag = sender_ctx.seal_in_place_detached(&mut ciphertext, associated_data)?;
        Ok(Ciphered {
            encapped_key: EncappedKey(encapped_key),
            text: ciphertext,
            tag: Tag(tag),
        })
    }
}

impl BorshSerialize for PublicKey {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.to_bytes(), writer)
    }
}

impl BorshDeserialize for PublicKey {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        <Vec<u8> as BorshDeserialize>::deserialize_reader(reader).and_then(|buf| {
            Ok(Self::from_bytes(
                &<Vec<u8> as BorshDeserialize>::deserialize(&mut buf.as_slice())?,
            ))
        })
    }
}

impl SecretKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        hpke::Serializable::to_bytes(&self.0).into()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hpke::Deserializable::from_bytes(bytes).expect("invalid bytes"))
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, hpke::HpkeError> {
        Ok(Self(hpke::Deserializable::from_bytes(bytes)?))
    }

    pub fn decrypt(
        &self,
        cipher: &Ciphered,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, hpke::HpkeError> {
        // Decapsulate and derive the shared secret. This creates a shared AEAD context.
        let mut receiver_ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &self.0,
            &cipher.encapped_key.0,
            INFO_ENTROPY,
        )?;

        // On success, open_in_place_detached() will decrypt the ciphertext in place
        let mut plaintext = cipher.text.to_vec();
        receiver_ctx.open_in_place_detached(&mut plaintext, associated_data, &cipher.tag.0)?;
        Ok(plaintext)
    }

    /// Get the public key associated with this secret key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(<Kem as hpke::Kem>::sk_to_pk(&self.0))
    }
}

pub fn generate() -> (SecretKey, PublicKey) {
    let mut csprng = <rand::rngs::StdRng as rand::SeedableRng>::from_entropy();
    let (sk, pk) = <Kem as hpke::Kem>::gen_keypair(&mut csprng);
    (SecretKey(sk), PublicKey(pk))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_encrypt_decrypt() {
        let (sk, pk) = super::generate();
        let msg = b"hello world";
        let associated_data = b"associated data";

        let cipher = pk.encrypt(msg, associated_data).unwrap();
        let decrypted = sk.decrypt(&cipher, associated_data).unwrap();

        assert_eq!(msg, &decrypted[..]);
    }

    #[test]
    fn test_serialization_format() {
        let sk_hex = "cf3df427dc1377914349b592cfff8deb4b9f8ab1cc4baa8e8e004b6502ac1ca0";
        let pk_hex = "0e6d143bff1d67f297ac68cb9be3667e38f1dc2b244be48bf1d6c6bd7d367c3c";

        let sk = super::SecretKey::try_from_bytes(&hex::decode(sk_hex).unwrap()).unwrap();
        let pk = super::PublicKey::try_from_bytes(&hex::decode(pk_hex).unwrap()).unwrap();
        assert_eq!(sk.public_key(), pk);
    }
}
