use std::fmt;

use {PublicKey, PrivateKey};

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use PublicKey::*;
        match *self {
            Rsa { .. } => {
                // TODO(tailhook) show length
                write!(f, "PublicKey::Rsa")
            }
            Ed25519(..) => {
                write!(f, "PublicKey::Ed25519")
            }
        }
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use PrivateKey::*;
        match *self {
            Rsa { .. } => {
                // TODO(tailhook) show length
                write!(f, "PrivateKey::Rsa")
            }
            Ed25519(..) => {
                write!(f, "PrivateKey::Ed25519")
            }
        }
    }
}
