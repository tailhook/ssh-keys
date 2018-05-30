use std::io::{Read};
use std::path::Path;
use std::fs::File;

extern crate ssh_keys;

use ssh_keys::{PrivateKey, PublicKey};


fn read_file<T: AsRef<Path>>(path: T) -> String {
    let mut f = File::open(path).unwrap();
    let mut buf = String::with_capacity(128);
    f.read_to_string(&mut buf).unwrap();
    return buf;
}

#[test]
fn invalid_key() {
    assert!(ssh_keys::openssh::parse_private_key(
            "-----BEGIN OPENSSH PRIVATE KEY------END OPENSSH PRIVATE KEY-----"
        ).is_err());
}

#[test]
fn ed25519() {
    let key = ssh_keys::openssh::parse_private_key(
            &read_file("test-keys/ed25519")
        ).unwrap();
    assert_eq!(key, vec![PrivateKey::Ed25519(
        [110, 136, 165, 108, 69, 111, 107, 140, 8, 233, 44, 143, 173, 86, 111,
        3, 185, 15, 63, 68, 44, 99, 208, 109, 77, 114, 203, 229, 227, 142,
        174, 65, 182, 135, 254, 94, 168, 107, 218, 136, 69, 10, 76, 17, 52,
        204, 42, 119, 218, 188, 182, 42, 243, 239, 135, 37, 87, 29, 93, 143,
        143, 19, 101, 42]
    )]);
}

#[test]
fn ed25519_private_to_public() {
    let key = ssh_keys::openssh::parse_private_key(
            &read_file("test-keys/ed25519")
        ).unwrap();
    let public = key[0].public_key();
    assert_eq!(public, PublicKey::Ed25519(
        [182, 135, 254, 94, 168, 107, 218, 136, 69, 10, 76, 17, 52, 204, 42,
        119, 218, 188, 182, 42, 243, 239, 135, 37, 87, 29, 93, 143, 143, 19,
        101, 42]));
}

#[test]
fn rsa1024new() {
    let key = ssh_keys::openssh::parse_private_key(
            &read_file("test-keys/rsa1024new")
        ).unwrap();
    assert_eq!(key, vec![PrivateKey::Rsa {
        n: vec![0, 192, 166, 107, 240, 134, 128, 206, 93, 25, 64, 151, 249, 97,
            90, 225, 72, 185, 15, 161, 178, 57, 32, 96, 20, 201, 50, 30, 49,
            166, 66, 181, 82, 234, 124, 154, 23, 127, 201, 182, 228, 79, 83,
            164, 199, 85, 3, 114, 246, 43, 154, 164, 36, 97, 54, 219, 175, 9,
            237, 228, 187, 112, 78, 95, 104, 96, 15, 16, 225, 124, 214, 101,
            255, 87, 58, 98, 233, 157, 15, 88, 47, 139, 43, 177, 161, 190,
            188, 8, 38, 24, 168, 5, 151, 213, 104, 228, 73, 251, 66, 132, 226,
            168, 224, 251, 226, 196, 49, 41, 18, 62, 98, 0, 64, 34, 235, 217,
            198, 199, 85, 15, 34, 186, 199, 119, 97, 92, 117, 187, 51],
        e: vec![1, 0, 1],
        d: vec![35, 50, 196, 233, 239, 73, 61, 107, 25, 32, 10, 36, 80, 59, 80,
            137, 254, 245, 242, 47, 35, 236, 220, 97, 47, 217, 110, 86, 215,
            239, 188, 61, 104, 6, 88, 9, 15, 26, 5, 198, 117, 15, 237, 61, 86,
            53, 9, 30, 29, 29, 101, 252, 23, 158, 244, 72, 104, 226, 4, 54,
            146, 240, 94, 209, 219, 248, 93, 95, 71, 66, 81, 121, 46, 207,
            194, 24, 234, 163, 243, 195, 135, 178, 60, 32, 228, 144, 1, 135,
            36, 11, 10, 102, 113, 40, 244, 133, 224, 32, 181, 126, 197, 12,
            244, 5, 206, 100, 68, 205, 51, 216, 106, 188, 181, 54, 161, 14, 7,
            104, 233, 44, 246, 63, 218, 41, 21, 213, 195, 161],
        iqmp: vec![0, 179, 64, 166, 163, 241, 79, 124, 96, 202, 73, 78, 186,
            49, 105, 243, 201, 43, 243, 152, 195, 51, 252, 45, 25, 78, 243,
            69, 173, 89, 247, 165, 146, 14, 211, 11, 221, 64, 140, 147, 183,
            46, 20, 66, 231, 65, 250, 105, 209, 130, 254, 89, 14, 9, 122, 224,
            109, 106, 8, 227, 31, 40, 120, 115, 64],
        p: vec![0, 229, 203, 98, 47, 238, 77, 208, 83, 235, 122, 103, 69, 74,
            196, 173, 2, 58, 236, 182, 185, 62, 176, 217, 60, 20, 168, 139,
            18, 25, 200, 151, 4, 103, 167, 174, 87, 116, 203, 217, 167, 11,
            53, 159, 11, 172, 159, 130, 222, 8, 41, 230, 141, 112, 14, 168,
            249, 23, 62, 226, 135, 213, 135, 165, 43],
        q: vec![0, 214, 158, 165, 64, 92, 0, 42, 178, 76, 142, 235, 42, 69, 70,
            54, 138, 105, 122, 162, 18, 176, 87, 173, 127, 251, 80, 94, 167,
            133, 173, 67, 194, 238, 215, 56, 230, 189, 77, 152, 136, 53, 203,
            159, 139, 126, 134, 179, 38, 127, 196, 240, 0, 194, 170, 146, 85,
            243, 34, 74, 219, 38, 234, 206, 25],
    }]);
}

#[test]
fn rsa1024() {
    let key = ssh_keys::openssh::parse_private_key(
            &read_file("test-keys/rsa1024")
        ).unwrap();
    assert_eq!(key, vec![PrivateKey::Rsa {
        n: vec![0, 192, 166, 107, 240, 134, 128, 206, 93, 25, 64, 151, 249, 97,
            90, 225, 72, 185, 15, 161, 178, 57, 32, 96, 20, 201, 50, 30, 49,
            166, 66, 181, 82, 234, 124, 154, 23, 127, 201, 182, 228, 79, 83,
            164, 199, 85, 3, 114, 246, 43, 154, 164, 36, 97, 54, 219, 175, 9,
            237, 228, 187, 112, 78, 95, 104, 96, 15, 16, 225, 124, 214, 101,
            255, 87, 58, 98, 233, 157, 15, 88, 47, 139, 43, 177, 161, 190,
            188, 8, 38, 24, 168, 5, 151, 213, 104, 228, 73, 251, 66, 132, 226,
            168, 224, 251, 226, 196, 49, 41, 18, 62, 98, 0, 64, 34, 235, 217,
            198, 199, 85, 15, 34, 186, 199, 119, 97, 92, 117, 187, 51],
        e: vec![1, 0, 1],
        d: vec![35, 50, 196, 233, 239, 73, 61, 107, 25, 32, 10, 36, 80, 59, 80,
            137, 254, 245, 242, 47, 35, 236, 220, 97, 47, 217, 110, 86, 215,
            239, 188, 61, 104, 6, 88, 9, 15, 26, 5, 198, 117, 15, 237, 61, 86,
            53, 9, 30, 29, 29, 101, 252, 23, 158, 244, 72, 104, 226, 4, 54,
            146, 240, 94, 209, 219, 248, 93, 95, 71, 66, 81, 121, 46, 207,
            194, 24, 234, 163, 243, 195, 135, 178, 60, 32, 228, 144, 1, 135,
            36, 11, 10, 102, 113, 40, 244, 133, 224, 32, 181, 126, 197, 12,
            244, 5, 206, 100, 68, 205, 51, 216, 106, 188, 181, 54, 161, 14, 7,
            104, 233, 44, 246, 63, 218, 41, 21, 213, 195, 161],
        iqmp: vec![0, 179, 64, 166, 163, 241, 79, 124, 96, 202, 73, 78, 186,
            49, 105, 243, 201, 43, 243, 152, 195, 51, 252, 45, 25, 78, 243,
            69, 173, 89, 247, 165, 146, 14, 211, 11, 221, 64, 140, 147, 183,
            46, 20, 66, 231, 65, 250, 105, 209, 130, 254, 89, 14, 9, 122, 224,
            109, 106, 8, 227, 31, 40, 120, 115, 64],
        p: vec![0, 229, 203, 98, 47, 238, 77, 208, 83, 235, 122, 103, 69, 74,
            196, 173, 2, 58, 236, 182, 185, 62, 176, 217, 60, 20, 168, 139,
            18, 25, 200, 151, 4, 103, 167, 174, 87, 116, 203, 217, 167, 11,
            53, 159, 11, 172, 159, 130, 222, 8, 41, 230, 141, 112, 14, 168,
            249, 23, 62, 226, 135, 213, 135, 165, 43],
        q: vec![0, 214, 158, 165, 64, 92, 0, 42, 178, 76, 142, 235, 42, 69, 70,
            54, 138, 105, 122, 162, 18, 176, 87, 173, 127, 251, 80, 94, 167,
            133, 173, 67, 194, 238, 215, 56, 230, 189, 77, 152, 136, 53, 203,
            159, 139, 126, 134, 179, 38, 127, 196, 240, 0, 194, 170, 146, 85,
            243, 34, 74, 219, 38, 234, 206, 25],
    }]);
}

#[test]
fn rsa1024_pub() {
    let key = ssh_keys::openssh::parse_private_key(
            &read_file("test-keys/rsa1024")
        ).unwrap();
    let public = key[0].public_key();
    assert_eq!(public, PublicKey::Rsa {
        exponent: vec![1, 0, 1],
        modulus: vec![0, 192, 166, 107, 240, 134, 128, 206, 93, 25, 64, 151,
            249, 97, 90, 225, 72, 185, 15, 161, 178, 57, 32, 96, 20, 201, 50,
            30, 49, 166, 66, 181, 82 , 234, 124, 154, 23, 127, 201, 182, 228,
            79, 83, 164, 199, 85, 3, 114, 246, 43, 154, 164, 36, 97, 54, 219,
            175, 9, 237, 228, 187, 112, 78, 95, 104, 96, 15, 16 , 225, 124,
            214, 101, 255, 87, 58, 98, 233, 157, 15, 88, 47, 139, 43, 177,
            161, 190, 188, 8, 38, 24, 168, 5, 151, 213, 104, 228, 73, 251, 66,
            132, 226, 168, 224, 251, 226, 196, 49, 41, 18, 62, 98, 0, 64, 34,
            235, 217, 198, 199, 85, 15, 34, 186, 199, 119, 97, 92, 117, 187,
            51],
    });
}
