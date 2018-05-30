use {PrivateKey, PublicKey};


impl PrivateKey {
    /// Return public key for this private key
    pub fn public_key(&self) -> PublicKey {
        match self {
            &PrivateKey::Ed25519(data) => {
                let mut ar = [0u8; 32];
                ar.copy_from_slice(&data[32..]);
                PublicKey::Ed25519(ar)
            }
            &PrivateKey::Rsa { ref e, ref n, .. } => {
                PublicKey::Rsa { exponent: e.clone(), modulus: n.clone() }
            }
        }
    }
}
