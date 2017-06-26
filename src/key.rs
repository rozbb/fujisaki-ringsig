use curve25519_dalek::constants::DECAF_ED25519_BASEPOINT;
use curve25519_dalek::decaf::{CompressedDecaf, DecafPoint};
use curve25519_dalek::scalar::Scalar;
use rand::OsRng;

/// A public key
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey(pub(crate) DecafPoint);

impl PublicKey {
    /// Serialize this public key to 32 bytes
    pub fn as_bytes(&self) -> Vec<u8> {
        let c = self.0.compress();
        c.as_bytes().to_vec()
    }

    // TODO: Make this more robust
    /// Deserialize this public key from 32 bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<PublicKey> {
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        let c = CompressedDecaf(arr);
        c.decompress().map(|p| PublicKey(p))
    }
}

/// A private key
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateKey(pub(crate) Scalar, pub(crate) DecafPoint);

impl PrivateKey {
    /// Serialize this private key to 64 bytes
    pub fn as_bytes(&self) -> Vec<u8> {
        let privkey_bytes = self.0.as_bytes().to_vec();
        let pubkey_bytes = {
            let p = PublicKey(self.1.clone());
            p.as_bytes()
        };

        [privkey_bytes, pubkey_bytes].concat()
    }

    // TODO: Make more robust
    /// Deserialize this private key from 64 bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<PrivateKey> {
        if bytes.len() != 64 {
            return None;
        }
        let (scalar_bytes, pubkey_point_bytes) = bytes.split_at(32);

        let scalar = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(scalar_bytes);
            Scalar(arr)
        };
        let pubkey_point = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(pubkey_point_bytes);
            let c = CompressedDecaf(arr);
            c.decompress()
        };

        pubkey_point.map(|p| PrivateKey(scalar, p))
    }
}

/// A private and public keypair
#[derive(Clone)]
pub struct KeyPair {
    pub pubkey: PublicKey,
    pub privkey: PrivateKey,
}

impl KeyPair {
    /// Generate a secure random keypair
    pub fn generate() -> KeyPair {
        let mut csprng = OsRng::new().expect("Could not instantiate CSPRNG");
        let s = Scalar::random(&mut csprng);
        let pubkey = PublicKey(&s * &DECAF_ED25519_BASEPOINT);
        let privkey = PrivateKey(s, pubkey.0.clone());

        KeyPair { pubkey, privkey }
    }
}

#[cfg(test)]
mod test {
    use super::{KeyPair, PrivateKey, PublicKey};

    #[test]
    fn test_key_serialization_correctness() {
        let KeyPair { pubkey, privkey } = KeyPair::generate();

        let pubkey_bytes = pubkey.as_bytes();
        assert_eq!(PublicKey::from_bytes(&*pubkey_bytes), Some(pubkey));

        let privkey_bytes = privkey.as_bytes();
        assert_eq!(PrivateKey::from_bytes(&*privkey_bytes), Some(privkey));
    }

    #[test]
    fn test_key_serialization_robustness() {
        // 31 bytes should be too short for anything
        let bytes = [1u8; 31];
        assert_eq!(PublicKey::from_bytes(&bytes), None);
        assert_eq!(PrivateKey::from_bytes(&bytes), None);
    }
}
