use std::io::{Read};
use std::path::Path;
use std::fs::File;

extern crate ssh_keys;

use ssh_keys::PrivateKey;


fn read_file<T: AsRef<Path>>(path: T) -> String {
    let mut f = File::open(path).unwrap();
    let mut buf = String::with_capacity(128);
    f.read_to_string(&mut buf).unwrap();
    return buf;
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
