//! Parser of OpenSSH keys
//!
//! Key formats supported:
//!
//! * `ssh-rsa`
//! * `ssh-ed25519`
//!
//! Both ASN1 and openssh-key-v1 format supported.
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

struct Asn1<'a> {
    data: &'a [u8],
    offset: usize,
}


/// Parse a single SSH public key in openssh format
pub fn parse_public_key(line: &str) -> Result<PublicKey, Error> {
    let mut iter = line.split_whitespace();
    let kind = iter.next().ok_or(Error::InvalidFormat)?;
    let data = iter.next().ok_or(Error::InvalidFormat)?;
    let buf = b64decode(data.as_bytes())?;

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

fn b64decode(data: &[u8]) -> Result<Vec<u8>, Error> {
    base64::decode_config(data, base64::Config::new(
        base64::CharacterSet::Standard,
        /*pad*/ true,
        /*strip_whitepace*/ true,
        base64::LineWrap::NoWrap, // irrelevant
    ))
    .map_err(|_| Error::InvalidFormat)
}

/// Parse a SSH private key in openssh format
///
/// Note new format of SSH key can potentially contain more than one key
pub fn parse_private_key(data: &str) -> Result<Vec<PrivateKey>, Error> {
    if data.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
        let end = data.find("-----END RSA PRIVATE KEY-----")
            .ok_or(Error::InvalidFormat)?;
        let start = match (data[..end].find("\n\n"),
                           data[..end].find("\r\n\r\n"))
        {
            (Some(x), Some(y)) if x < y => x,
            (Some(_), Some(y)) => y,
            (Some(x), None) => x,
            (None, Some(y)) => y,
            (None, None) => "-----BEGIN RSA PRIVATE KEY-----".len(),
        };
        let data = b64decode(data[start..end].trim().as_bytes())?;
        let mut cur = Asn1::new(&data);
        let mut items = cur.sequence()?;
        let ver = items.read_short_int()?;
        if ver != 0 {
            return Err(Error::UnsupportedType(format!("version {}", ver)));
        }
        let n = items.read_big_int()?;
        let e = items.read_big_int()?;
        let d = items.read_big_int()?;
        let p = items.read_big_int()?;
        let q = items.read_big_int()?;
        let _x = items.read_big_int()?;
        let _y = items.read_big_int()?;
        let iqmp = items.read_big_int()?;
        return Ok(vec![PrivateKey::Rsa {
            n: n.to_vec(), e: e.to_vec(), d: d.to_vec(),
            iqmp: iqmp.to_vec(),
            p: p.to_vec(), q: q.to_vec(),
        }]);
    } else if data.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
        let start = "-----BEGIN OPENSSH PRIVATE KEY-----".len();
        let end = data.find("-----END OPENSSH PRIVATE KEY-----")
            .ok_or(Error::InvalidFormat)?;
        if start >= end {
            return Err(Error::InvalidFormat);
        }
        let data = b64decode(data[start..end].trim().as_bytes())?;
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
                        "ssh-rsa" => {
                            let n = pcur.read_bytes()?;
                            let e = pcur.read_bytes()?;
                            let d = pcur.read_bytes()?;
                            let iqmp = pcur.read_bytes()?;
                            let p = pcur.read_bytes()?;
                            let q = pcur.read_bytes()?;
                            let _comment = pcur.read_string()?;
                            result.push(PrivateKey::Rsa {
                                n: n.to_vec(), e: e.to_vec(), d: d.to_vec(),
                                iqmp: iqmp.to_vec(),
                                p: p.to_vec(), q: q.to_vec(),
                            })
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


/// A limited ASN1 (DER) parser suitable to decode RSA key
impl<'a> Asn1<'a>  {
    pub fn new(data: &[u8]) -> Asn1 {
        Asn1 {
            data: data,
            offset: 0,
        }
    }
    fn read_len(&mut self) -> Result<usize, Error> {
        if self.offset >= self.data.len() {
            return Err(Error::InvalidFormat);
        }
        let lbyte = self.data[self.offset];
        self.offset += 1;
        if lbyte == 128 || lbyte == 255 {
            return Err(Error::InvalidFormat);
        }
        if lbyte & 128 == 0 {
            return Ok(lbyte as usize);
        }
        let nbytes = (lbyte & 127) as usize;
        if self.data.len() < self.offset + nbytes {
            return Err(Error::InvalidFormat);
        }
        let mut result: usize = 0;
        for i in 0..nbytes {
            result = result.checked_mul(256).ok_or(Error::InvalidFormat)?
                     + self.data[self.offset+i] as usize;
        }
        self.offset += nbytes;
        return Ok(result);
    }
    pub fn sequence(&mut self) -> Result<Asn1<'a>, Error> {
        if self.offset >= self.data.len() {
            return Err(Error::InvalidFormat);
        }
        let byte = self.data[self.offset];
        // Universal, construct, sequence
        if byte != (0 << 6) | (1 << 5) | 16 {
            return Err(Error::InvalidFormat);
        }
        self.offset += 1;
        let bytes = self.read_len()?;
        if self.offset+bytes > self.data.len() {
            return Err(Error::InvalidFormat);
        }
        let res = Asn1::new(&self.data[self.offset..self.offset+bytes]);
        self.offset += bytes;
        return Ok(res);
    }
    pub fn read_big_int(&mut self) -> Result<&'a [u8], Error> {
        if self.offset >= self.data.len() {
            return Err(Error::InvalidFormat);
        }
        let byte = self.data[self.offset];
        // Universal, primitive, integer
        if byte != (0 << 6) | (0 << 5) | 2 {
            return Err(Error::InvalidFormat);
        }
        self.offset += 1;
        let len = self.read_len()?;
        if self.data.len() < self.offset + len {
            return Err(Error::InvalidFormat);
        }
        let result = &self.data[self.offset..self.offset + len];
        self.offset += len;
        return Ok(result);
    }
    pub fn read_short_int(&mut self) -> Result<u8, Error> {
        let data = self.read_big_int()?;
        if data.len() != 1 {
            return Err(Error::InvalidFormat);
        }
        return Ok(data[0]);
    }
}
