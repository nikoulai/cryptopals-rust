use set1::utils::hex_to_bytes;
// use sha1_smol::Digest;
use super::sha1::{compute, pad_message, Block};

pub fn main() {}

pub fn sha1_mac(key: &[u8], message: &[u8]) -> String {
    // let input = pad_message(&key.to_vec()).unwrap();
    // let hash1 = compute(input).unwrap();

    let mut input = Vec::with_capacity(key.len() + message.len());
    input.extend_from_slice(key);

    input.extend_from_slice(message);
    let shainput = pad_message(&input).unwrap();
    compute(shainput).unwrap()
}

//previous implementations for sha1-smol
// pub fn sha1_mac_bytes(key: &[u8], message: &[u8]) -> [u8; 20] {
//     let d = sha1_mac(key, message);
//     d.bytes()
// }
//
// pub fn sha1_mac_string(key: &[u8], message: &[u8]) -> String {
//     let d = sha1_mac(key, message);
//     d.to_string()
// }

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    pub fn test_sha1_mac() {
        assert_eq!(
            sha1_mac("".as_bytes(), "Hello World!".as_bytes()),
            "2ef7bde608ce5404e97d5f042f95f89f1c232871"
        );

        let hashed = sha1_mac(b"key", b"message");
        assert_eq!(hashed, "7d89ca5f9535d3bd925ca99f484ae4413a14fe2d");

        let hashed = sha1_mac(b"notthekey", b"message");
        assert_ne!(hashed, "7d89ca5f9535d3bd925ca99f484ae4413a14fe2d");
    }
}
