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
            Rsa { ref n, ref e, ref d, ref iqmp, ref p, ref q }
            => Rsa { n: n.clone(), e: e.clone(), d: d.clone(),
                     iqmp: iqmp.clone(), p: p.clone(), q: q.clone() },
        }
    }
}

// We have to implement his manually because PartialEq doesnt work for [u8; 64]
impl PartialEq for PrivateKey {
    fn eq(&self, other: &PrivateKey) -> bool {
        use PrivateKey::*;
        match (self, other) {
            (&Rsa { n: ref n1, e: ref e1, d: ref d1, iqmp: ref iqmp1,
                    p: ref p1, q: ref q1 },
             &Rsa { n: ref n2, e: ref e2, d: ref d2, iqmp: ref iqmp2,
                    p: ref p2, q: ref q2 }
            ) => {
                n1 == n2 && e1 == e2 && d1 == d2 && iqmp1 == iqmp2 &&
                p1 == p2 && q1 == q2
            }
            (&Rsa {..}, _) => false,
            (&Ed25519(ref d1), &Ed25519(ref d2)) => &d1[..] == &d2[..],
            (&Ed25519(..), _) => false,
        }

    }
}

impl Eq for PrivateKey { }
