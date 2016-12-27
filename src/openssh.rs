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


use {PublicKey, PrivateKey, Error};

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

/// Parse a SSH privte key in openssh format
pub fn parse_private_key(data: &str) -> Result<Vec<PrivateKey>, Error> {
    if data.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
        let start = match (data.find("\n\n"), data.find("\r\n\r\n")) {
            (Some(x), Some(y)) if x < y => x,
            (Some(_), Some(y)) => y,
            (Some(x), None) => x,
            (None, Some(y)) => y,
            (None, None) => return Err(Error::InvalidFormat),
        };
        let end = data.find("-----END RSA PRIVATE KEY-----")
            .ok_or(Error::InvalidFormat)?;
        let data = base64::decode_ws(&data[start..end])
            .map_err(|_| Error::InvalidFormat)?;
        println!("DATA {:?}", data);
        unimplemented!();
    } else if data.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
        let start = "-----BEGIN OPENSSH PRIVATE KEY-----".len();
        let end = data.find("-----END OPENSSH PRIVATE KEY-----")
            .ok_or(Error::InvalidFormat)?;
        let data = base64::decode_ws(&data[start..end].trim())
            .map_err(|_| Error::InvalidFormat)?;
        let end = data.iter().position(|&x| x == 0)
            .ok_or(Error::InvalidFormat)?;
        let kind = from_utf8(&data[..end]).map_err(|_| Error::InvalidFormat)?;
        match kind {
            "openssh-key-v1" => {
                let mut cur = Cursor::new(&data[end+1..]);
                let cipher_name = cur.read_string()?;
                let kdf_name = cur.read_string()?;
                let opt = cur.read_string()?;
                if cipher_name != "none" || kdf_name != "none" || opt != "" {
                    return Err(Error::Encrypted);
                }
                let num_keys = cur.read_int()?;
                let mut result = Vec::new();
                for _ in 0..num_keys {
                    let _pub_key = cur.read_bytes()?;
                    let priv_key = cur.read_bytes()?;
                    let mut pcur = Cursor::new(priv_key);
                    let c1 = pcur.read_int()?;
                    let c2 = pcur.read_int()?;
                    if c1 != c2 {
                        return Err(Error::InvalidFormat);
                    }
                    let key_type = pcur.read_string()?;
                    match key_type {
                        "ssh-ed25519" => {
                            let _pub_key = pcur.read_bytes()?;
                            let priv_key = pcur.read_bytes()?;
                            let _comment = pcur.read_string()?;

                            let mut array_key = [0u8; 64];
                            array_key.copy_from_slice(priv_key);
                            result.push(PrivateKey::Ed25519(array_key));
                        }
                        _ => {
                            return Err(Error::UnsupportedType(
                                key_type.to_string()));
                        }
                    }
                }
                return Ok(result);
            }
            _ => return Err(Error::UnsupportedType(kind.to_string())),
        }
    } else {
        Err(Error::UnsupportedType("unknown".to_string()))
    }
}

impl<'a> Cursor<'a> {
    pub fn new(data: &[u8]) -> Cursor {
        Cursor {
            data: data,
            offset: 0,
        }
    }
    fn read_int(&mut self) -> Result<u32, Error> {
        let cur = &self.data[self.offset..];
        if cur.len() < 4 {
            return Err(Error::InvalidFormat);
        }
        self.offset += 4;
        return Ok(BigEndian::read_u32(&cur[..4]));
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

