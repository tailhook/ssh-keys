//! Parser of OpenSSH keys
//!
//! Key formats supported:
//!
//! * `ssh-rsa`
//! * `ssh-ed25519`
//!
//! Password-protected private keys are not supported yet

use std::str::from_utf8;

use base64;
use byteorder::{BigEndian, ByteOrder};


use {PublicKey, Error};

struct Cursor<'a> {
    data: &'a [u8],
    offset: usize,
}


/// Parse a single SSH public key in openssh format
pub fn parse_public_key(line: &str) -> Result<PublicKey, Error> {
    let mut iter = line.split_whitespace();
    let kind = iter.next().ok_or(Error::InvalidFormat)?;
    let data = iter.next().ok_or(Error::InvalidFormat)?;
    let buf = base64::decode(data).map_err(|_| Error::InvalidFormat)?;

    let mut cur = Cursor::new(&buf);
    let int_kind = cur.read_string()?;
    if int_kind != int_kind {
        return Err(Error::InvalidFormat);
    }

    match kind {
        "ssh-rsa" => {
            let e = cur.read_bytes()?;
            let n = cur.read_bytes()?;
            Ok(PublicKey::Rsa { exponent: e.to_vec(), modulus: n.to_vec() })
        }
        "ssh-ed25519" => {
            let key = cur.read_bytes()?;
            if key.len() != 32 {
                return Err(Error::InvalidFormat);
            }
            let mut array_key = [0u8; 32];
            array_key.copy_from_slice(key);
            Ok(PublicKey::Ed25519(array_key))
        }
        _ => Err(Error::UnsupportedType(kind.to_string()))
    }
}

impl<'a> Cursor<'a> {
    pub fn new(data: &[u8]) -> Cursor {
        Cursor {
            data: data,
            offset: 0,
        }
    }
    fn read_bytes(&mut self) -> Result<&'a [u8], Error> {
        let cur = &self.data[self.offset..];
        if cur.len() < 4 {
            return Err(Error::InvalidFormat);
        }
        let len = BigEndian::read_u32(&cur[..4]) as usize;
        if cur.len() < len + 4 {
            return Err(Error::InvalidFormat);
        }
        self.offset += len + 4;
        return Ok(&cur[4..len+4]);
    }
    fn read_string(&mut self) -> Result<&'a str, Error> {
        from_utf8(self.read_bytes()?)
        .map_err(|_| Error::InvalidFormat)
    }
}

