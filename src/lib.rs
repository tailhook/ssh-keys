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
    Ed25519([u8; 32]),
}

/// Secret key enum
pub enum PrivateKey {
    /// RSA key
    #[allow(missing_docs)]
    Rsa { n: Vec<u8>, e: Vec<u8>, d: Vec<u8>, iqmp: Vec<u8>,
          p: Vec<u8>, q: Vec<u8> },
    /// Ed25519 (eliptic curves) key
    Ed25519([u8; 64]),
}
