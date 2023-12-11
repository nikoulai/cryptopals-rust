use set1::utils::hex_to_bytes;
use sha1_smol;
use sha1_smol::Digest;

pub fn main() {}

pub fn sha1_mac(key: &[u8], message: &[u8]) -> Digest {
    let mut m = sha1_smol::Sha1::new();

    m.update(key);

    m.update(message);

    m.digest()
}

pub fn sha1_mac_bytes(key: &[u8], message: &[u8]) -> [u8; 20] {
    let d = sha1_mac(key, message);
    d.bytes()
}

pub fn sha1_mac_string(key: &[u8], message: &[u8]) -> String {
    let d = sha1_mac(key, message);
    d.to_string()
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    pub fn test_sha1_mac() {
        assert_eq!(
            sha1_mac_bytes("".as_bytes(), "Hello World!".as_bytes()),
            hex_to_bytes("2ef7bde608ce5404e97d5f042f95f89f1c232871").as_slice()
        );

        let hashed = sha1_mac_bytes(b"key", b"message");
        assert_eq!(
            hashed,
            hex_to_bytes("7d89ca5f9535d3bd925ca99f484ae4413a14fe2d").as_slice()
        );

        let hashed = sha1_mac_bytes(b"notthekey", b"message");
        assert_ne!(
            hashed,
            hex_to_bytes("7d89ca5f9535d3bd925ca99f484ae4413a14fe2d").as_slice()
        );
    }
}
