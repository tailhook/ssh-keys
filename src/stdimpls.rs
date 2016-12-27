use {PublicKey, PrivateKey};


// We have to implement his manually because Clone doesnt work for [u8; 64]
impl Clone for PublicKey {
    fn clone(&self) -> PublicKey {
        use PublicKey::*;
        match *self {
            Rsa { ref exponent, ref modulus } => {
                Rsa { exponent: exponent.clone(), modulus: modulus.clone() }
            }
            Ed25519(data) => Ed25519(data),
        }
    }
}

// We have to implement his manually because PartialEq doesnt work for [u8; 64]
impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        use PublicKey::*;
        match (self, other) {
            (&Rsa { exponent: ref e1, modulus: ref n1 },
             &Rsa { exponent: ref e2, modulus: ref n2 })
            => e1 == e2 && n1 == n2,
            (&Rsa {..}, _) => false,
            (&Ed25519(ref d1), &Ed25519(ref d2)) => d1 == d2,
            (&Ed25519(..), _) => false,
        }

    }
}

impl Eq for PublicKey { }


// We have to implement his manually because Clone doesnt work for [u8; 64]
impl Clone for PrivateKey {
    fn clone(&self) -> PrivateKey {
        use PrivateKey::*;
        match *self {
            Ed25519(data) => Ed25519(data),
        }
    }
}

// We have to implement his manually because PartialEq doesnt work for [u8; 64]
impl PartialEq for PrivateKey {
    fn eq(&self, other: &PrivateKey) -> bool {
        use PrivateKey::*;
        match (self, other) {
            (&Ed25519(ref d1), &Ed25519(ref d2)) => &d1[..] == &d2[..],
        }

    }
}

impl Eq for PrivateKey { }
