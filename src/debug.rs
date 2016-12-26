use std::fmt;

use {PublicKey};

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
