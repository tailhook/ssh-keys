//! Public and private key parser
//!
//! The only key format supported so far is ``openssh``.
//!
#![warn(missing_docs)]

extern crate base64;
extern crate byteorder;
#[macro_use] extern crate quick_error;

mod error;
mod debug;
mod stdimpls;
pub mod openssh;

pub use error::Error;

/// Public key enum
pub enum PublicKey {
    /// RSA key
    #[allow(missing_docs)]
    Rsa { exponent: Vec<u8>, modulus: Vec<u8> },
    /// Ed25519 (eliptic curves) key
    Ed25519([u8; 32])
}

/// Secret key enum
pub enum PrivateKey {
    /// RSA key
    //Rsa { exponent: , modulus }
    /// Ed25519 (eliptic curves) key
    Ed25519([u8; 64])
}
